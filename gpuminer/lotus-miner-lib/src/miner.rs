use ocl::{
    builders::{DeviceSpecifier, ProgramBuilder},
    Buffer, Context, Device, Kernel, Platform, Queue,
};
use sha2::Digest;
use std::{
    convert::TryInto,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};
use eyre::Result;
use thiserror::Error;
use log::{debug, info, error};
use chrono::Local;

use crate::{sha256::lotus_hash, block::Block, Log};

/// OpenCL kernel code for the Lotus miner.
/// 
/// NOTE FOR DEVELOPERS:
/// This file contains two kernel implementations embedded directly into the binary at compile time:
/// 1. LOTUS_OG_KERNEL - The default kernel optimized for Lotus mining
/// 2. POCLBM_KERNEL - An alternative kernel based on the poclbm project
///
/// Both kernels are embedded to eliminate the need to distribute kernel files alongside the binary,
/// providing a more convenient and reliable distribution.
/// 
/// The kernel selection can be controlled via the `--kernel-type` command-line parameter:
/// - `lotus_og` (default): Uses the Lotus original kernel
/// - `poclbm`: Uses the POCLBM-based kernel
/// 
/// To modify the kernels:
/// 1. Edit the original files at gpuminer/kernels/lotus_og.cl or gpuminer/kernels/poclbm120327.cl
/// 2. Rebuild the project - the include_str! macro will automatically pull in the new content
const LOTUS_OG_KERNEL: &str = include_str!("../../kernels/lotus_og.cl");
const POCLBM_KERNEL: &str = include_str!("../../kernels/poclbm120327.cl");

// Counter for successful shares/blocks found
static SHARES_FOUND: AtomicU64 = AtomicU64::new(0);
static HASHES_PROCESSED: AtomicU64 = AtomicU64::new(0);
static MINING_START_TIME: once_cell::sync::Lazy<Instant> = once_cell::sync::Lazy::new(|| Instant::now());

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("Ocl error: {0:?}")]
    Ocl(ocl::Error)
}

#[derive(Debug, Clone)]
pub struct MiningSettings {
    pub local_work_size: i32,
    pub kernel_size: u32,
    pub inner_iter_size: i32,
    pub sleep: u32,
    pub gpu_indices: Vec<usize>,
    pub kernel_type: KernelType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KernelType {
    LotusOG,
    POCLBM,
}

impl std::fmt::Display for KernelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelType::LotusOG => write!(f, "lotus_og"),
            KernelType::POCLBM => write!(f, "poclbm"),
        }
    }
}

impl Default for KernelType {
    fn default() -> Self {
        KernelType::LotusOG
    }
}

pub struct Miner {
    search_kernel: Kernel,
    header_buffer: Buffer<u32>,
    buffer: Buffer<u32>,
    settings: MiningSettings,
    kernel_type: KernelType,
}

#[derive(Debug, Clone, Copy)]
pub struct Work {
    header: [u8; 160],
    target: [u8; 32],
    pub nonce_idx: u32,
}

impl From<ocl::Error> for MinerError {
    fn from(err: ocl::Error) -> Self {
        MinerError::Ocl(err)
    }
}

use self::MinerError::*;

impl Work {
    pub fn from_header(header: [u8; 160], target: [u8; 32]) -> Work {
        Work {
            header,
            target,
            nonce_idx: 0,
        }
    }

    pub fn set_big_nonce(&mut self, big_nonce: u64) {
        self.header[44..52].copy_from_slice(&big_nonce.to_le_bytes());
    }

    pub fn header(&self) -> &[u8; 160] {
        &self.header
    }
}

impl Default for Work {
    fn default() -> Self {
        Work {
            header: [0; 160],
            target: [0; 32],
            nonce_idx: 0,
        }
    }
}

pub fn format_hashes(value: u64) -> String {
    let units = ["H", "kH", "MH", "GH", "TH", "PH", "EH", "ZH", "YH"];
    let mut unit = 0;
    let mut float_value = value as f64;
    while float_value >= 1000.0 && unit < units.len() - 1 {
        float_value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", format_number(value), units[unit])
    } else {
        format!("{:.2} {}", float_value, units[unit])
    }
}

pub fn format_number(value: u64) -> String {
    let s = value.to_string();
    let mut chars = s.chars().rev().collect::<Vec<_>>();
    for i in (3..chars.len()).step_by(4) {
        chars.insert(i, ',');
    }
    chars.into_iter().rev().collect()
}

// Format bytes as B, kB, MB, GB, etc.
pub fn format_bytes(value: u64) -> String {
    let units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let mut unit = 0;
    let mut float_value = value as f64;
    while float_value >= 1000.0 && unit < units.len() - 1 {
        float_value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", format_number(value), units[unit])
    } else {
        format!("{:.2} {}", float_value, units[unit])
    }
}

// Format hashes, with optional /s for hashrate
pub fn format_hashes_per_sec(value: u64) -> String {
    let units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s", "ZH/s", "YH/s"];
    let mut unit = 0;
    let mut float_value = value as f64;
    while float_value >= 1000.0 && unit < units.len() - 1 {
        float_value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", format_number(value), units[unit])
    } else {
        format!("{:.2} {}", float_value, units[unit])
    }
}

fn mining_runtime_stats() -> String {
    let runtime = MINING_START_TIME.elapsed();
    let hours = runtime.as_secs() / 3600;
    let minutes = (runtime.as_secs() % 3600) / 60;
    let seconds = runtime.as_secs() % 60;
    
    let total_shares = SHARES_FOUND.load(Ordering::Relaxed);
    let total_hashes = HASHES_PROCESSED.load(Ordering::Relaxed);
    
    // Calculate shares per hour
    let shares_per_hour = if runtime.as_secs() > 0 {
        (total_shares as f64 * 3600.0) / runtime.as_secs() as f64
    } else {
        0.0
    };
    
    format!(
        "⏱️ Runtime: {:02}:{:02}:{:02} | 🎯 Shares: {} | 📊 Shares/h: {:.2} | 💯 Total hashes: {}",
        hours, minutes, seconds, format_number(total_shares), shares_per_hour, format_hashes(total_hashes)
    )
}

impl Miner {
    pub fn setup(settings: MiningSettings) -> Result<Self> {
        info!("🛠️ Setting up OpenCL miner");
        
        // List platforms to get platform id
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err(eyre::eyre!("No OpenCL platforms found").into());
        }
        
        info!("🔍 Scanning for OpenCL platforms and devices...");
        for (platform_idx, platform) in platforms.iter().enumerate() {
            let platform_name = platform.name().unwrap_or_else(|_| String::from("<invalid platform>"));
            info!("🖥️ Platform {}: {}", platform_idx, platform_name);
            
            match Device::list_all(platform) {
                Ok(devices) => {
                    for (device_idx, device) in devices.iter().enumerate() {
                        let device_name = device.name().unwrap_or_else(|_| String::from("<invalid device>"));
                        info!("  🎮 Device {}: {}", device_idx, device_name);
                    }
                },
                Err(e) => {
                    error!("❌ Error listing devices for platform {}: {:?}", platform_name, e);
                }
            }
        }
        
        // Find the specified platform/device index
        let mut platform_device = None;
        let mut gpu_index = 0;
        for platform in platforms {
            if let Ok(devices) = Device::list_all(&platform) {
                for device in devices {
                    if settings.gpu_indices.contains(&gpu_index) {
                        platform_device = Some((platform.clone(), device));
                        break;
                    }
                    gpu_index += 1;
                }
            }
            if platform_device.is_some() {
                break;
            }
        }
        
        let (platform, device) = platform_device.ok_or_else(|| eyre::eyre!("No suitable GPU found! Check your GPU index."))?;
        
        let platform_name = platform.name().unwrap_or_else(|_| String::from("Unknown platform"));
        let device_name = device.name().unwrap_or_else(|_| String::from("Unknown device"));
        info!("✅ Selected GPU: {} from platform: {}", device_name, platform_name);
        
        // Create context with the selected device
        let context = Context::builder()
            .platform(platform)
            .devices(DeviceSpecifier::Single(device.clone()))
            .build()?;
            
        debug!("🔧 OpenCL context created successfully");
        
        // Create command queue
        let queue = Queue::new(&context, device, None)?;
        debug!("🔄 Command queue created successfully");
        
        // Setup and build the kernels using embedded kernel code
        let mut prog_builder = ProgramBuilder::new();
        
        // Use the embedded kernel code based on the selected kernel type
        let kernel_code = match settings.kernel_type {
            KernelType::LotusOG => LOTUS_OG_KERNEL,
            KernelType::POCLBM => POCLBM_KERNEL,
        };
        
        // Log which kernel is being used
        info!("🔄 Using {} kernel", match settings.kernel_type {
            KernelType::LotusOG => "Lotus Original (lotus_og)",
            KernelType::POCLBM => "POCLBM",
        });
        
        // Adjust work group sizes and optimization parameters based on kernel type
        let (local_work_size, inner_iter_size) = match settings.kernel_type {
            KernelType::LotusOG => (settings.local_work_size, settings.inner_iter_size),
            KernelType::POCLBM => {
                // POCLBM kernel often works better with these values
                let poclbm_local_size = 64; // Common value for POCLBM kernel
                let poclbm_inner_size = 8;  // Reduced value to avoid work group size issues
                
                info!("🔧 Adjusting POCLBM kernel parameters: local_work_size={}, inner_iter_size={}",
                      poclbm_local_size, poclbm_inner_size);
                      
                (poclbm_local_size, poclbm_inner_size)
            }
        };
        
        prog_builder
            .src(kernel_code)
            .cmplr_def("WORKSIZE", local_work_size)
            .cmplr_def("ITERATIONS", inner_iter_size);
        
        // Add device to program
        prog_builder.devices(DeviceSpecifier::Single(device));
        
        info!("🔨 Building OpenCL program from embedded kernel...");
        let program = prog_builder.build(&context)?;
        info!("✅ OpenCL program built successfully");
        
        // Create kernel and buffers
        let mut kernel_builder = Kernel::builder();
        kernel_builder
            .program(&program)
            .name("search")
            .queue(queue.clone());
            
        let buffer = Buffer::builder().len(0xff).queue(queue.clone()).build()?;
        let header_buffer = Buffer::builder().len(0xff).queue(queue).build()?;
        
        debug!("🧠 OpenCL buffers allocated successfully");
        
        // Create the kernel with appropriate arguments based on kernel type
        let search_kernel = match settings.kernel_type {
            KernelType::LotusOG => {
                kernel_builder
                    .arg_named("offset", 0u32)
                    .arg_named("partial_header", None::<&Buffer<u32>>)
                    .arg_named("output", None::<&Buffer<u32>>)
                    .build()?
            },
            KernelType::POCLBM => {
                // Use the same simple 3-argument structure for POCLBM as was used in the original implementation
                // This is a simpler approach than the previous 28-argument setup
                info!("🔄 Using simplified 3-argument structure for POCLBM kernel");
                kernel_builder
                    .arg_named("offset", 0u32)
                    .arg_named("partial_header", None::<&Buffer<u32>>)
                    .arg_named("output", None::<&Buffer<u32>>)
                    .build()?
            }
        };
            
        info!(
            "🚀 Lotus miner initialized with kernel size {} ({} bytes), ready to mine!",
            crate::miner::format_bytes(settings.kernel_size as u64),
            crate::miner::format_number(settings.kernel_size as u64)
        );
        
        // Create the miner with the kernel type
        let kernel_type = settings.kernel_type;
        
        Ok(Miner {
            search_kernel,
            buffer,
            header_buffer,
            settings,
            kernel_type,
        })
    }

    pub fn list_device_names() -> Vec<String> {
        let platforms = match Platform::list().len() {
            0 => {
                error!("❌ No OpenCL platforms found! Make sure your GPU drivers are properly installed.");
                vec![]
            },
            _ => Platform::list()
        };
        
        let mut device_names = Vec::new();
        for platform in platforms.iter() {
            let platform_name = platform.name().unwrap_or("<invalid platform>".to_string());
            let devices = match Device::list_all(platform) {
                Ok(devices) => devices,
                Err(e) => {
                    error!("❌ Error listing devices for platform {}: {:?}", platform_name, e);
                    continue;
                }
            };
            
            for device in devices.iter() {
                let device_name = device.name().unwrap_or("<invalid device>".to_string());
                info!("💻 Found device: {} on platform {}", device_name, platform_name);
                device_names.push(format!(
                    "{} - {}",
                    platform_name,
                    device_name
                ));
            }
        }
        
        if device_names.is_empty() {
            error!("⚠️ No OpenCL compatible devices found! Check your GPU drivers.");
        } else {
            info!("🎉 Found {} OpenCL compatible device(s)", device_names.len());
        }
        
        device_names
    }

    pub fn has_nonces_left(&self, work: &Work) -> bool {
        work.nonce_idx
            .checked_mul(self.settings.kernel_size)
            .is_some()
    }

    pub fn num_nonces_per_search(&self) -> u64 {
        self.settings.kernel_size as u64 * self.settings.inner_iter_size as u64
    }

    pub fn find_nonce(&mut self, work: &Work, log: &Log) -> Result<Option<u64>> {
        let base = match work
            .nonce_idx
            .checked_mul(self.num_nonces_per_search().try_into().unwrap())
        {
            Some(base) => base,
            None => {
                log.error(
                    "🚨 Error: Nonce base overflow, skipping. This could be fixed by lowering rpc_poll_interval.",
                    Some("Miner")
                );
                return Ok(None);
            }
        };
        
        // Track the time it takes to process this batch
        let batch_start = Instant::now();
        
        let mut partial_header = [0u8; 84];
        partial_header[..52].copy_from_slice(&work.header[..52]);
        partial_header[52..].copy_from_slice(&sha2::Sha256::digest(&work.header[52..]));
        let mut partial_header_ints = [0u32; 21];
        for (chunk, int) in partial_header.chunks(4).zip(partial_header_ints.iter_mut()) {
            *int = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        
        debug!("🧮 Processing nonce batch starting at base: {}", base);
        
        // Write header data to buffer
        self.header_buffer.write(&partial_header_ints[..]).enq().map_err(Ocl)?;
        
        // Use the mine method to set the kernel arguments based on kernel type
        match self.kernel_type {
            KernelType::LotusOG => {
                // Set the arguments for Lotus OG kernel
                self.search_kernel
                    .set_arg("offset", base).map_err(Ocl)?;
                self.search_kernel
                    .set_arg("partial_header", &self.header_buffer).map_err(Ocl)?;
                self.search_kernel
                    .set_arg("output", &self.buffer).map_err(Ocl)?;
            },
            KernelType::POCLBM => {
                // Use the same simple argument setting for POCLBM
                self.search_kernel
                    .set_arg("offset", base).map_err(Ocl)?;
                self.search_kernel
                    .set_arg("partial_header", &self.header_buffer).map_err(Ocl)?;
                self.search_kernel
                    .set_arg("output", &self.buffer).map_err(Ocl)?;
            }
        }
        
        let mut vec = vec![0; self.buffer.len()];
        self.buffer.write(&vec).enq().map_err(Ocl)?;
        
        // Setup kernel execution with appropriate work group size based on kernel type
        let cmd = match self.kernel_type {
            KernelType::LotusOG => {
                // For Lotus OG kernel, we can use the original settings
                self.search_kernel
                    .cmd()
                    .global_work_size(self.settings.kernel_size)
            },
            KernelType::POCLBM => {
                // For POCLBM kernel, we need to set both global and local work sizes
                // The POCLBM kernel typically requires a local work size that is a power of 2
                // and meets alignment requirements
                let local_work_size = 64; // Common value that works on most GPUs
                debug!("🔧 Using local_work_size={} for POCLBM kernel", local_work_size);
                
                self.search_kernel
                    .cmd()
                    .global_work_size(self.settings.kernel_size)
                    .local_work_size(local_work_size)
            }
        };
        
        unsafe {
            cmd.enq().map_err(Ocl)?;
        }
        self.buffer.read(&mut vec).enq().map_err(Ocl)?;
        
        // Update total hashes processed
        let hashes_in_batch = self.num_nonces_per_search();
        let _current_total = HASHES_PROCESSED.fetch_add(hashes_in_batch, Ordering::Relaxed);
        
        // Calculate batch speed
        let batch_time = batch_start.elapsed();
        let speed = if batch_time.as_secs_f64() > 0.0 {
            hashes_in_batch as f64 / batch_time.as_secs_f64() / 1_000_000.0
        } else {
            0.0
        };
        
        if work.nonce_idx % 100 == 0 {
            debug!("⚡ Batch speed: {:.2} MH/s | {}", speed, mining_runtime_stats());
        }
        
        if vec[0x80] != 0 {
            let mut header = work.header;
            'nonce: for &nonce in &vec[..0x7f] {
                let nonce = nonce.swap_bytes();
                if nonce != 0 {
                    header[44..48].copy_from_slice(&nonce.to_le_bytes());
                    let result_nonce = u64::from_le_bytes(header[44..52].try_into().unwrap());
                    let hash = lotus_hash(&header);
                    let mut candidate_hash = hash;
                    candidate_hash.reverse();
                    
                    log.info(
                        format!(
                            "🔍 Candidate: nonce={}, hash={}",
                            result_nonce,
                            hex::encode(&candidate_hash)
                        ),
                        Some("Share")
                    );
                    
                    if hash.last() != Some(&0) {
                        log.bug(
                            "🐞 Bug: found nonce's hash has no leading zero byte. Contact the developers.",
                            Some("Share")
                        );
                    }
                    
                    for (&h, &t) in hash.iter().zip(work.target.iter()).rev() {
                        if h > t {
                            continue 'nonce;
                        }
                        if t > h {
                            // Increment share counter
                            let shares = SHARES_FOUND.fetch_add(1, Ordering::Relaxed) + 1;
                            let _timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
                            
                            // Celebratory log message with stats
                            log.info(
                                format!("💰 Found valid share #{} at nonce {} 💰", shares, result_nonce),
                                Some("Share")
                            );
                            log.info(
                                format!("🎊 Hash: {} 🎊", hex::encode(&candidate_hash)),
                                Some("Share")
                            );
                            log.info(
                                format!("📊 Stats: {}", mining_runtime_stats()),
                                Some("Share")
                            );
                            
                            return Ok(Some(result_nonce));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn set_intensity(&mut self, intensity: i32) {
        self.settings.kernel_size = 1 << intensity;
        info!("🔥 Mining intensity set to {} (kernel size: {})", intensity, self.settings.kernel_size);
    }

    pub fn update_gpu_index(&mut self, gpu_index: i64) -> Result<()> {
        if self.settings.gpu_indices[0] == gpu_index as usize {
            info!("ℹ️ GPU index {} is already selected, no change needed", gpu_index);
            return Ok(());
        }
        
        info!("🔄 Switching to GPU with index {}", gpu_index);
        let mut settings = self.settings.clone();
        settings.gpu_indices = vec![gpu_index.try_into().unwrap()];
        *self = Miner::setup(settings)?;
        info!("✅ Successfully switched to GPU with index {}", gpu_index);
        Ok(())
    }

    pub fn execute_round(&mut self, work: &Work, log: &Log) -> Result<()> {
        debug!("🔄 Executing mining round");
        
        // Create a temporary Block to demonstrate using the body methods
        let tmp_block = Block::empty();
        debug!("Block body size: {}", tmp_block.body_size());
        let _body_bytes = tmp_block.get_body();
        
        // Log some mining information including the body data
        log.info(
            format!(
                "🧮 Mining with header: {} | Body size: {}",
                hex::encode(&work.header[..16]), // Show part of the header
                tmp_block.body_size()
            ),
            Some("Miner")
        );
        
        // Proceed with standard mining operation
        match self.find_nonce(work, log) {
            Ok(Some(nonce)) => {
                log.info(format!("💎 Found potential solution with nonce: {}", nonce), Some("Share"));
            }
            Ok(None) => {
                debug!("⏭️ Round completed without finding a solution");
            }
            Err(e) => {
                log.error(format!("❌ Error during mining: {:?}", e), Some("Miner"));
            }
        }
        
        Ok(())
    }
}
