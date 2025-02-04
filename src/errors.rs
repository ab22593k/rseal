use std::{error, io};

use thiserror::Error;

/// Error type for memory sealing operations
#[derive(Debug)]
pub enum RSealMemError {
    /// Error during allocation
    AllocationError,

    /// Error during sealing
    SealError(RSealError),

    /// Invalid size or alignment
    InvalidParameters(&'static str),
}

impl error::Error for RSealMemError {}

#[derive(Debug, Error)]
pub enum RSealError {
    /// Error when invalid arguments are provided to mseal
    #[error("Invalid arguments provided to mseal: {0}")]
    InvalidInput(String),

    /// Error when memory allocation fails during mseal
    #[error("Memory allocation error during mseal: {0}")]
    MemoryError(String),

    /// Error when permissions are insufficient for mseal
    #[error("Permission error during mseal: {0}")]
    PermissionError(String),

    /// Unhandled or unexpected error from mseal
    #[error("Unknown error from mseal: {0}")]
    UnknownError(String),

    /// Standard I/O error
    #[error("IO Error: {0}")]
    IOError(#[from] io::Error),

    /// Error when mseal syscall is not implemented
    #[error("mseal syscall not implemented: {0}")]
    SyscallNotImplemented(String),
}
