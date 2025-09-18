use std::time::Duration;
use std::str::FromStr;

use log::{info, error, debug, LevelFilter};
use lotus_miner_lib::{
    logger::{LoggerConfig, init_global_logger},
    ConfigSettings, Server,
    miner::KernelType,
};
use clap::Parser;

/// 🌸 Lotus GPU Miner CLI
///
/// ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
/// ┃  High-performance OpenCL miner for the Lotus chain  ┃
/// ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
///
/// Welcome to the Lotus GPU Miner!
///
/// Authors:
///   Alexandre Guillioud - FrenchBTC <alexandre@burnlotus.org>
///   Tobias Ruck <ruck.tobias@gmail.com>
///
/// Example usage:
///   lotus-miner-cli -g 0 -s 25 -o lotus_16PSJNgWFFf14otE17Fp43HhjbkFchk4Xgvwy2X27 -i 1 -a https://burnlotus.org --poolmining
///
/// Features:
///   - Self-contained binary with embedded OpenCL kernel
///   - Zero-stall mining architecture
///   - Hashrate stabilization with 60-second moving average
///   - Multiple kernel options (Lotus OG and POCLBM)
///
/// For more information, visit: https://github.com/Boblepointu/lotusd/blob/master/gpuminer/README.md
#[derive(Parser, Debug)]
#[clap(
    name = "Lotus GPU Miner",
    version,
    author = "Alexandre Guillioud - FrenchBTC <alexandre@burnlotus.org>, Tobias Ruck <ruck.tobias@gmail.com>",
    about = "🌸 High-performance OpenCL miner for the Lotus blockchain.",
    long_about = None,
    after_help = "\
EXAMPLES:\n  lotus-miner-cli -g 0 -s 25 -o lotus_16PSJNgWFFf14otE17Fp43HhjbkFchk4Xgvwy2X27 -i 1 -a https://burnlotus.org --poolmining\n\nKernel Types:\n  - lotus_og (default): Optimized kernel for Lotus mining\n  - poclbm: Alternative kernel based on poclbm project\n\nSelf-contained binary with embedded OpenCL kernels - no external files needed!\n\nFor more information, visit: https://github.com/Boblepointu/lotusd/blob/master/gpuminer/README.md\n\nDeveloped by Alexandre Guillioud (FrenchBTC - alexandre@burnlotus.org) and Tobias Ruck (ruck.tobias@gmail.com).\n"
)]
struct Cli {
    /// Path to a configuration file in TOML format. Overrides defaults if present.
    #[clap(short, long, value_name = "CONFIG", help = "Configuration file (TOML)")]
    config: Option<String>,

    /// GPU index to use for mining (default: 0)
    #[clap(short = 'g', long, value_name = "gpu_index", help = "GPU index to use (default: 0)")]
    gpu_index: Option<i64>,

    /// Kernel size (work batch size, default: 23)
    #[clap(short = 's', long, value_name = "kernel_size", help = "Kernel size (default: 23)")]
    kernel_size: Option<i64>,

    /// Select the OpenCL kernel to use: 'lotus_og' (default) or 'poclbm'
    #[clap(long = "kernel-type", value_name = "kernel_type", help = "OpenCL kernel to use: 'lotus_og' or 'poclbm' (default: lotus_og)")]
    kernel_type: Option<String>,

    /// Address to receive mining rewards (mine-to address)
    #[clap(short = 'o', long, value_name = "mine_to_address", help = "Coinbase Output Address (mine-to address)")]
    mine_to_address: Option<String>,

    /// Password for Lotus RPC authentication
    #[clap(short = 'p', long, value_name = "rpc_password", help = "Lotus RPC password")]
    rpc_password: Option<String>,

    /// How often to poll the Lotus node for new work (seconds)
    #[clap(short = 'i', long, value_name = "rpc_poll_interval", help = "Lotus RPC getblocktemplate poll interval (seconds)")]
    rpc_poll_interval: Option<i64>,

    /// Lotus node RPC URL (e.g. http://127.0.0.1:10604 or https://burnlotus.org)
    #[clap(short = 'a', long, value_name = "rpc_url", help = "Lotus RPC address")]
    rpc_url: Option<String>,

    /// Username for Lotus RPC authentication
    #[clap(short = 'u', long, value_name = "rpc_user", help = "Lotus RPC username")]
    rpc_user: Option<String>,

    /// Enable pool mining mode (submit shares to a pool instead of solo mining)
    #[clap(short = 'm', long = "poolmining", help = "Enable pool mining mode")]
    pool_mining: bool,
    
    /// Enable verbose debugging output (shows detailed RPC logs)
    #[clap(long = "debug", help = "Enable verbose debugging output")]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Initialize the logger
    let logger_config = LoggerConfig {
        console_output: true,
        file_output: true,
        log_file_path: Some("lotus-miner.log".into()),
        max_log_entries: 1000,
        max_hashrate_entries: 1000,
        level: if cli.debug { LevelFilter::Debug } else { LevelFilter::Info },
    };

    // Initialize the global logger
    init_global_logger(logger_config).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    info!("Author: Alexandre Guillioud - FrenchBTC - https://burnlotus.org - alexandre@burnlotus.org - https://github.com/Boblepointu/lotusd");
    info!("🌸 Lotus GPU Miner CLI started");
    
    // Load configuration, giving priority to CLI args
    let mut settings = ConfigSettings::load(true)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    if let Some(ref v) = cli.gpu_index { settings.gpu_index = *v; }
    if let Some(ref v) = cli.kernel_size { settings.kernel_size = *v; }
    if let Some(ref v) = cli.kernel_type {
        settings.kernel_type = match KernelType::from_str(v) {
            Ok(kernel_type) => kernel_type,
            Err(e) => {
                error!("Invalid kernel type: {}. Using default instead.", e);
                KernelType::LotusOG
            }
        };
    }
    if let Some(ref v) = cli.mine_to_address { settings.mine_to_address = v.clone(); }
    if let Some(ref v) = cli.rpc_password { settings.rpc_password = v.clone(); }
    if let Some(ref v) = cli.rpc_poll_interval { settings.rpc_poll_interval = *v; }
    if let Some(ref v) = cli.rpc_url { settings.rpc_url = v.clone(); }
    if let Some(ref v) = cli.rpc_user { settings.rpc_user = v.clone(); }
    if cli.pool_mining { settings.pool_mining = true; }
    if let Some(ref _v) = cli.config {
        // Optionally, reload config from the specified file (not implemented here for brevity)
        // You can add logic to load from a custom config file if needed.
    }
    info!("✅ Configuration loaded successfully");
    
    // Add debug logs for configuration settings
    if cli.debug {
        debug!("🔧 Configuration details:");
        debug!("  - GPU Index: {}", settings.gpu_index);
        debug!("  - Kernel Size: {}", settings.kernel_size);
        debug!("  - Kernel Type: {}", settings.kernel_type);
        debug!("  - Mining Address: {}", settings.mine_to_address);
        debug!("  - RPC URL: {}", settings.rpc_url);
        debug!("  - RPC Poll Interval: {}", settings.rpc_poll_interval);
        debug!("  - Pool Mining: {}", settings.pool_mining);
    }

    // Start mining
    let report_interval = Duration::from_secs(5);
    info!("⏱️ Reporting hashrate every {} seconds (using 60s moving average with 15s warm-up period)", report_interval.as_secs());
    
    if cli.debug {
        info!("🔍 Debug mode enabled - showing detailed RPC logs");
    }

    // Create a handle to capture CTRL+C
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    ctrlc::set_handler(move || {
        if let Some(tx) = tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Create the mining server
    let server = Server::from_config(settings, report_interval);
    
    // Run the server
    let server_ref = std::sync::Arc::new(server);
    
    // Wait for CTRL+C or run the server directly
    tokio::select! {
        _ = rx => {
            info!("👋 Received shutdown signal, stopping miner...");
        }
        result = server_ref.run() => {
            match result {
                Ok(_) => info!("✅ Mining completed successfully"),
                Err(e) => error!("❌ Mining error: {}", e),
            }
        }
    }

    info!("🔄 Shutting down Lotus GPU Miner...");
    Ok(())
}
