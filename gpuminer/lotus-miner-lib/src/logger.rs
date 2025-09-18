use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use chrono::{DateTime, Local};
use log::{Level, LevelFilter, Log as LogTrait, Metadata, Record};
use thiserror::Error;
use colored::*;

/// Severity levels for logging, matching the log crate's levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    Debug,
    Info,
    Warn,
    Error,
    Bug,
}

impl From<Level> for LogSeverity {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => LogSeverity::Error,
            Level::Warn => LogSeverity::Warn,
            Level::Info => LogSeverity::Info,
            Level::Debug => LogSeverity::Debug,
            Level::Trace => LogSeverity::Debug,
        }
    }
}

impl From<LogSeverity> for Level {
    fn from(severity: LogSeverity) -> Self {
        match severity {
            LogSeverity::Debug => Level::Debug,
            LogSeverity::Info => Level::Info,
            LogSeverity::Warn => Level::Warn,
            LogSeverity::Error => Level::Error,
            LogSeverity::Bug => Level::Error,
        }
    }
}

/// A log entry containing a message, severity level, and timestamp
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub msg: String,
    pub severity: LogSeverity,
    pub timestamp: DateTime<Local>,
    pub tag: String,
    pub source: Option<String>,
}

impl Display for LogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = format!("{:<9}", self.tag).bold();
        let tag_colored = match self.tag.to_lowercase().as_str() {
            "status" => tag.bright_cyan(),
            "miner" => tag.bright_yellow(),
            "opencl" => tag.bright_green(),
            "hashrate" => tag.bright_magenta(),
            "share" => tag.bright_blue(),
            "shutdown" => tag.bright_red(),
            "rpc" => tag.bright_cyan(),
            _ => tag.white(),
        };
        let level_colored = match self.severity {
            LogSeverity::Debug => "DEBUG".bright_blue(),
            LogSeverity::Info => "Info".bright_white(),
            LogSeverity::Warn => "Warn".yellow(),
            LogSeverity::Error => "Error".red(),
            LogSeverity::Bug => "Bug".magenta(),
        };
        write!(
            f,
            "[{}] [{}] [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            tag_colored,
            level_colored,
            self.msg
        )
    }
}

impl From<LogRecord> for LogEntry {
    fn from(record: LogRecord) -> Self {
        LogEntry {
            msg: record.msg,
            severity: record.severity,
            timestamp: record.timestamp,
            tag: record.tag,
        }
    }
}

/// Compatibility struct for existing code
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub msg: String,
    pub severity: LogSeverity,
    pub timestamp: DateTime<Local>,
    pub tag: String,
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = format!("{:<9}", self.tag).bold();
        let tag_colored = match self.tag.to_lowercase().as_str() {
            "status" => tag.bright_cyan(),
            "miner" => tag.bright_yellow(),
            "opencl" => tag.bright_green(),
            "hashrate" => tag.bright_magenta(),
            "share" => tag.bright_blue(),
            "shutdown" => tag.bright_red(),
            _ => tag.white(),
        };
        let level_colored = match self.severity {
            LogSeverity::Debug => "Debug".bright_black(),
            LogSeverity::Info => "Info".bright_white(),
            LogSeverity::Warn => "Warn".yellow(),
            LogSeverity::Error => "Error".red(),
            LogSeverity::Bug => "Bug".magenta(),
        };
        write!(
            f,
            "[{}] [{}] [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            tag_colored,
            level_colored,
            self.msg
        )
    }
}

impl From<LogEntry> for LogRecord {
    fn from(entry: LogEntry) -> Self {
        LogRecord {
            msg: entry.msg,
            severity: entry.severity,
            timestamp: entry.timestamp,
            tag: entry.tag,
            source: None,
        }
    }
}

impl From<&LogEntry> for LogRecord {
    fn from(entry: &LogEntry) -> Self {
        LogRecord {
            msg: entry.msg.clone(),
            severity: entry.severity,
            timestamp: entry.timestamp,
            tag: entry.tag.clone(),
            source: None,
        }
    }
}

/// An entry for tracking hashrate with a timestamp
#[derive(Debug, Clone)]
pub struct HashrateEntry {
    pub hashrate: f64,
    pub timestamp: DateTime<Local>,
}

impl Display for HashrateEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} Hashrate {:.3} MH/s",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            self.hashrate / 1_000_000.0
        )
    }
}

/// Errors that can occur during logging operations
#[derive(Debug, Error)]
pub enum LoggerError {
    #[error("Failed to initialize logger: {0}")]
    InitError(std::io::Error),
    
    #[error("Logger not initialized")]
    NotInitialized,
    
    #[error("Failed to set logger: {0}")]
    SetLogger(String),
    
    #[error("Logger already initialized")]
    AlreadyInitialized,
    
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    
    #[error("Set logger error: {0}")]
    SetLoggerError(String),
    
    #[error("Failed to acquire lock: {0}")]
    LockError(String),
}

impl From<std::io::Error> for LoggerError {
    fn from(err: std::io::Error) -> Self {
        LoggerError::IoError(err)
    }
}

/// Configuration for the logger
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Whether to log to stdout
    pub console_output: bool,
    
    /// Whether to log to a file
    pub file_output: bool,
    
    /// Path to the log file (if file_output is true)
    pub log_file_path: Option<PathBuf>,
    
    /// Maximum number of log entries to keep in memory
    pub max_log_entries: usize,
    
    /// Maximum number of hashrate entries to keep in memory
    pub max_hashrate_entries: usize,
    
    /// Minimum log level to record
    pub level: LevelFilter,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            console_output: true,
            file_output: false,
            log_file_path: None,
            max_log_entries: 1000,
            max_hashrate_entries: 1000,
            level: LevelFilter::Info,
        }
    }
}

/// The main logger struct
pub struct Logger {
    logs: RwLock<Vec<LogRecord>>,
    hashrates: RwLock<Vec<HashrateEntry>>,
    config: RwLock<LoggerConfig>,
    file: RwLock<Option<File>>,
}

impl Logger {
    /// Create a new logger with the given configuration
    pub fn new(config: LoggerConfig) -> Result<Arc<Self>, LoggerError> {
        let file = if config.file_output {
            if let Some(path) = &config.log_file_path {
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(file)
            } else {
                None
            }
        } else {
            None
        };
        
        let logger = Arc::new(Self {
            logs: RwLock::new(Vec::with_capacity(config.max_log_entries)),
            hashrates: RwLock::new(Vec::with_capacity(config.max_hashrate_entries)),
            config: RwLock::new(config),
            file: RwLock::new(file),
        });
        
        Ok(logger)
    }
    
    /// Initialize the logger as the global logger for the log crate
    pub fn init(logger: Arc<Logger>) -> Result<(), LoggerError> {
        let level = {
            let config = logger
                .config
                .read()
                .map_err(|e| LoggerError::LockError(e.to_string()))?;
            config.level
        };
        
        log::set_max_level(level);
        log::set_logger(Box::leak(Box::new(LoggerWrapper(logger))))
            .map_err(|e| LoggerError::SetLogger(e.to_string()))
    }
    
    /// Log a message with the given severity
    pub fn log(&self, record: impl Into<LogRecord>) {
        let record = record.into();
        
        // Print to console if enabled
        if let Ok(config) = self.config.read() {
            if config.console_output {
                println!("{}", record);
            }
            
            // Write to file if enabled
            if config.file_output {
                if let Ok(mut file_guard) = self.file.write() {
                    if let Some(file) = file_guard.as_mut() {
                        let _ = writeln!(file, "{}", record);
                        let _ = file.flush();
                    }
                }
            }
        }
        
        // Store in memory
        if let Ok(mut logs) = self.logs.write() {
            logs.push(record);
            
            // Trim if exceeding max size
            if let Ok(config) = self.config.read() {
                if logs.len() > config.max_log_entries {
                    let to_keep = config.max_log_entries;
                    let len = logs.len();
                    logs.drain(0..len - to_keep);
                }
            }
        }
    }
    
    /// Log a message with the given severity
    pub fn log_str(&self, msg: impl ToString, severity: LogSeverity, tag: Option<&str>) {
        self.log(LogRecord {
            msg: msg.to_string(),
            severity,
            timestamp: Local::now(),
            tag: tag.unwrap_or("General").to_string(),
            source: None,
        });
    }
    
    /// Log an info message
    pub fn info(&self, msg: impl ToString, tag: Option<&str>) {
        self.log_str(msg, LogSeverity::Info, tag);
    }
    
    /// Log a warning message
    pub fn warn(&self, msg: impl ToString, tag: Option<&str>) {
        self.log_str(msg, LogSeverity::Warn, tag);
    }
    
    /// Log an error message
    pub fn error(&self, msg: impl ToString, tag: Option<&str>) {
        self.log_str(msg, LogSeverity::Error, tag);
    }
    
    /// Log a bug message
    pub fn bug(&self, msg: impl ToString, tag: Option<&str>) {
        self.log_str(msg, LogSeverity::Bug, tag);
    }
    
    /// Log a debug message
    pub fn debug(&self, msg: impl ToString, tag: Option<&str>) {
        // Only log if debug level is enabled
        if let Ok(config) = self.config.read() {
            if config.level >= LevelFilter::Debug {
                self.log_str(msg, LogSeverity::Debug, tag);
            }
        }
    }
    
    /// Get all logs
    pub fn get_logs(&self) -> Vec<LogRecord> {
        self.logs.read().map(|logs| logs.clone()).unwrap_or_default()
    }
    
    /// Get all logs and clear the log buffer
    pub fn get_logs_and_clear(&self) -> Vec<LogEntry> {
        if let Ok(mut logs) = self.logs.write() {
            let result: Vec<LogEntry> = logs.drain(..).map(|r| r.into()).collect();
            result
        } else {
            Vec::new()
        }
    }
    
    /// Report a hashrate
    pub fn report_hashrate(&self, hashrate: f64) {
        let entry = HashrateEntry {
            hashrate,
            timestamp: Local::now(),
        };
        // Log the hashrate with emoji and formatted value
        let formatted = crate::miner::format_hashes_per_sec(hashrate as u64);
        self.info(format!("💯 Hashrate: {}", formatted), Some("General"));
        // Store in memory
        if let Ok(mut hashrates) = self.hashrates.write() {
            hashrates.push(entry);
            // Trim if exceeding max size
            if let Ok(config) = self.config.read() {
                if hashrates.len() > config.max_hashrate_entries {
                    let to_keep = config.max_hashrate_entries;
                    let len = hashrates.len();
                    hashrates.drain(0..len - to_keep);
                }
            }
        }
    }
    
    /// Get all hashrates
    pub fn hashrates(&self) -> Vec<HashrateEntry> {
        self.hashrates.read().map(|h| h.clone()).unwrap_or_default()
    }
    
    /// Get read access to the hashrates
    pub fn hashrates_read<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, Vec<HashrateEntry>> {
        self.hashrates.read().unwrap()
    }
    
    /// Set the log level
    pub fn set_level(&self, level: LevelFilter) -> Result<(), LoggerError> {
        let mut config = self.config.write().map_err(|e| LoggerError::LockError(e.to_string()))?;
        config.level = level;
        log::set_max_level(level);
        Ok(())
    }
    
    /// Enable or disable console output
    pub fn set_console_output(&self, enabled: bool) -> Result<(), LoggerError> {
        let mut config = self.config.write().map_err(|e| LoggerError::LockError(e.to_string()))?;
        config.console_output = enabled;
        Ok(())
    }
    
    /// Enable or disable file output and set the file path
    pub fn set_file_output(&self, enabled: bool, path: Option<PathBuf>) -> Result<(), LoggerError> {
        let mut config = self.config.write().map_err(|e| LoggerError::LockError(e.to_string()))?;
        config.file_output = enabled;
        config.log_file_path = path.clone();
        
        let mut file_guard = self.file.write().map_err(|e| LoggerError::LockError(e.to_string()))?;
        *file_guard = if enabled {
            if let Some(path) = path {
                Some(OpenOptions::new().write(true).create(true).append(true).open(path)?)
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(())
    }
}

/// Implements the backward compatibility with the existing Log struct
pub struct Log {
    inner: Arc<Logger>,
}

impl Log {
    pub fn new() -> Self {
        // Create a default logger
        let config = LoggerConfig::default();
        let logger = Logger::new(config).unwrap();
        
        // Try to initialize it as the global logger
        let _ = Logger::init(Arc::clone(&logger));
        
        Self { inner: logger }
    }
    
    pub fn log(&self, entry: impl Into<LogEntry>) {
        let entry = entry.into();
        let record: LogRecord = (&entry).into();
        self.inner.log(record);
    }
    
    pub fn log_str(&self, msg: impl ToString, severity: LogSeverity, tag: Option<&str>) {
        self.inner.log_str(msg, severity, tag);
    }
    
    pub fn info(&self, msg: impl ToString, tag: Option<&str>) {
        self.inner.info(msg, tag);
    }
    
    pub fn warn(&self, msg: impl ToString, tag: Option<&str>) {
        self.inner.warn(msg, tag);
    }
    
    pub fn error(&self, msg: impl ToString, tag: Option<&str>) {
        self.inner.error(msg, tag);
    }
    
    pub fn bug(&self, msg: impl ToString, tag: Option<&str>) {
        self.inner.bug(msg, tag);
    }
    
    /// Log a debug message
    pub fn debug(&self, msg: impl ToString, tag: Option<&str>) {
        self.inner.debug(msg, tag);
    }
    
    pub fn get_logs_and_clear(&self) -> Vec<LogEntry> {
        self.inner.get_logs_and_clear()
    }
    
    pub fn report_hashrate(&self, hashrate: f64) {
        self.inner.report_hashrate(hashrate);
    }
    
    pub fn hashrates<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, Vec<HashrateEntry>> {
        self.inner.hashrates_read()
    }
}

/// Wrapper for the Logger to implement the log::Log trait
struct LoggerWrapper(Arc<Logger>);

impl LogTrait for LoggerWrapper {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if let Ok(config) = self.0.config.read() {
            metadata.level() <= config.level
        } else {
            // If we can't read the config, assume enabled
            true
        }
    }
    
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let severity = LogSeverity::from(record.level());
            self.0.log(LogRecord {
                msg: record.args().to_string(),
                severity,
                timestamp: Local::now(),
                tag: "General".to_string(),
                source: None,
            });
        }
    }
    
    fn flush(&self) {
        if let Ok(file_guard) = self.0.file.write() {
            if let Some(file) = file_guard.as_ref() {
                let _ = file.sync_all();
            }
        }
    }
}

// Initialize a global static logger that can be accessed from anywhere
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the global logger with the given configuration
pub fn init_global_logger(config: LoggerConfig) -> Result<Arc<Logger>, LoggerError> {
    if LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Err(LoggerError::AlreadyInitialized);
    }
    
    // Create a new logger with the given configuration
    let logger = Logger::new(config.clone())?;
    
    // Initialize the logger
    Logger::init(Arc::clone(&logger)).map_err(|e| LoggerError::SetLoggerError(e.to_string()))?;
    
    // Mark the logger as initialized
    LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
    
    // Print the current log level to help debugging
    let level_str = match config.level {
        LevelFilter::Off => "Off",
        LevelFilter::Error => "Error",
        LevelFilter::Warn => "Warn",
        LevelFilter::Info => "Info",
        LevelFilter::Debug => "Debug",
        LevelFilter::Trace => "Trace",
    };
    
    println!("Logger initialized with level: {}", level_str);
    
    Ok(logger)
}

/// Get the global logger instance
pub fn get_global_logger() -> Result<Arc<Logger>, LoggerError> {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Err(LoggerError::NotInitialized);
    }
    
    // Since we can't directly access the logger from the log crate,
    // we'll create a new one with the current settings
    let config = LoggerConfig {
        level: log::max_level(),
        ..Default::default()
    };
    
    Logger::new(config)
}

/// Initialize the global logger with default configuration
pub fn init_default_logger() -> Result<Arc<Logger>, LoggerError> {
    init_global_logger(LoggerConfig::default())
}
