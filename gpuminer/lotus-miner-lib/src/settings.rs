use std::io::Write;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};
use crate::miner::KernelType;

// Custom implementation to allow string deserialization of KernelType
impl FromStr for KernelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lotus_og" => Ok(KernelType::LotusOG),
            "poclbm" => Ok(KernelType::POCLBM),
            _ => Err(format!("Unknown kernel type: {}. Valid options are 'lotus_og' or 'poclbm'", s)),
        }
    }
}

// Implement Serialize and Deserialize for KernelType
impl<'de> Deserialize<'de> for KernelType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for KernelType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            KernelType::LotusOG => serializer.serialize_str("lotus_og"),
            KernelType::POCLBM => serializer.serialize_str("poclbm"),
        }
    }
}

// Removed deprecated clap macros and APIs. All config loading is now handled directly below.

pub const DEFAULT_URL: &str = "http://127.0.0.1:10604";
pub const DEFAULT_USER: &str = "lotus";
pub const DEFAULT_PASSWORD: &str = "lotus";
pub const DEFAULT_RPC_POLL_INTERVAL: i64 = 3;
pub const FOLDER_DIR: &str = ".lotus-miner";
pub const DEFAULT_KERNEL_SIZE: i64 = 21;
pub const DEFAULT_GPU_INDEX: i64 = 0;
pub const DEFAULT_KERNEL_TYPE: KernelType = KernelType::LotusOG;

#[derive(Debug, Deserialize)]
pub struct ConfigSettings {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub rpc_poll_interval: i64,
    pub mine_to_address: String,
    pub kernel_size: i64,
    pub gpu_index: i64,
    pub pool_mining: bool,
    pub kernel_type: KernelType,
}

const DEFAULT_CONFIG_FILE_CONTENT: &str = r#"mine_to_address = "lotus_16PSJMStv9sve3DfhDpiwUCa7RtqkyNBoS8RjFZSt"
rpc_url = "http://127.0.0.1:10604"
rpc_poll_interval = 3
rpc_user = "lotus"
rpc_password = "lotus"
gpu_index = 0
kernel_size = 23
pool_mining = false
kernel_type = "lotus_og"
"#;

impl ConfigSettings {
    pub fn load(_expect_mine_to_address: bool) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Set defaults
        let home_dir = match dirs::home_dir() {
            Some(some) => some,
            None => return Err(ConfigError::Message("no home directory".to_string())),
        };
        s.set_default("rpc_url", DEFAULT_URL)?;
        s.set_default("rpc_poll_interval", DEFAULT_RPC_POLL_INTERVAL)?;
        s.set_default("rpc_user", DEFAULT_USER)?;
        s.set_default("rpc_password", DEFAULT_PASSWORD)?;
        s.set_default("kernel_size", DEFAULT_KERNEL_SIZE)?;
        s.set_default("gpu_index", DEFAULT_GPU_INDEX)?;
        s.set_default("mine_to_address", "lotus_16PSJMStv9sve3DfhDpiwUCa7RtqkyNBoS8RjFZSt")?;
        s.set_default("pool_mining", false)?;
        s.set_default("kernel_type", match DEFAULT_KERNEL_TYPE {
            KernelType::LotusOG => "lotus_og",
            KernelType::POCLBM => "poclbm",
        })?;

        // Load config from file
        let default_config = home_dir;
        let default_config_folder = default_config.join(FOLDER_DIR);
        let default_config_toml = default_config_folder.join("config.toml");
        let default_config = default_config_folder.join("config");
        let _default_config_str = default_config.to_str().unwrap();
        if !default_config_toml.exists() {
            if let Err(err) = std::fs::create_dir_all(&default_config_folder) {
                eprintln!(
                    "Error: Couldn't create default config folder {}: {}",
                    default_config_folder.to_string_lossy(),
                    err
                );
            }
            match std::fs::File::create(&default_config_toml) {
                Ok(mut file) => {
                    if let Err(err) = file.write_all(DEFAULT_CONFIG_FILE_CONTENT.as_bytes())
                    {
                        eprintln!(
                            "Error: Couldn't write default config toml file {}: {}",
                            default_config_toml.to_string_lossy(),
                            err
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Error: Couldn't create default config toml file {}: {}",
                        default_config_toml.to_string_lossy(),
                        err
                    );
                }
            };
        }
        s.merge(File::with_name(default_config_toml.to_str().unwrap()).required(false))?;

        // All CLI overrides are now handled in main.rs (lotus-miner-cli)

        s.try_into()
    }
}
