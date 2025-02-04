use errno::errno;
use libc::{syscall, EINVAL, ENOMEM, EPERM};

use crate::errors::RSealError;

/// Unsafe FFI wrapper for the mseal syscall.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with a raw syscall
/// and assumes the caller has validated the arguments passed to it.
///
/// - `addr`: Must be a valid pointer to a memory region that the process has allocated.
/// - `len`: Must be the length of the memory region in bytes, must be a multiple of page size.
/// - `flags`: Flags for the mseal operation.
unsafe fn raw_mseal(
    addr: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_ulong,
) -> libc::c_int {
    #[cfg(target_arch = "x86_64")]
    let syscall_num = libc::SYS_mseal as libc::c_long;
    #[cfg(not(target_arch = "x86_64"))]
    let syscall_num = SYS_mseal as libc::c_long;

    syscall(syscall_num, addr, len, flags) as libc::c_int
}

/// Seals a memory region using the mseal syscall, preventing further modifications to its memory protection.
///
/// # Arguments
///
/// * `addr`: A raw pointer to the start of the memory region. Must be page-aligned.
/// * `len`: The length of the memory region in bytes. Must be a multiple of the page size.
/// * `flags`: Flags for the mseal operation (currently must be 0 as per initial problem description).
///
/// # Safety
///
/// The `addr` pointer must be valid and point to a memory region that is:
/// 1. Allocated by the current process.
/// 2. Page-aligned.
/// 3. Of length `len` which is a multiple of the page size.
///
/// This function itself is marked `unsafe` because it's dealing with raw memory pointers
/// and system calls. However, it attempts to provide a slightly safer interface
/// by performing some basic validations and error handling.
///
/// # Errors
///
/// Returns `Result<(), SealError>` indicating success or failure. Errors can be:
///
/// * `SealError::InvalidInput`: If the input `addr` or `len` are invalid (null, not page-aligned, etc.).
/// * `SealError::MemoryError`: If there is an issue with the memory region (e.g., not allocated, wrong length).
/// * `SealError::PermissionError`: If the operation is not permitted (e.g., already sealed or other permissions issues).
/// * `SealError::UnknownError`: For any other unexpected error from the syscall.
/// * `SealError::IOError`: If there's a general I/O error during syscall execution.
pub unsafe fn seal_memory(
    addr: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_ulong,
) -> Result<(), RSealError> {
    if addr.is_null() {
        return Err(RSealError::InvalidInput("Address pointer is null".into()));
    }

    if len == 0 {
        return Err(RSealError::InvalidInput("Length cannot be zero".into()));
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as usize;
    if (addr as usize) % page_size != 0 {
        return Err(RSealError::InvalidInput(format!(
            "Address must be page-aligned ({} bytes)",
            page_size
        )));
    }

    if len % page_size != 0 {
        return Err(RSealError::InvalidInput(format!(
            "Length must be a multiple of page size ({} bytes)",
            page_size
        )));
    }

    let result = raw_mseal(addr, len, flags);

    if result == 0 {
        Ok(())
    } else {
        let current_errno = errno();
        match current_errno.0 {
            EINVAL => Err(RSealError::InvalidInput(format!(
                "EINVAL: Invalid argument to mseal: {}",
                current_errno
            ))),
            ENOMEM => Err(RSealError::MemoryError(format!(
                "ENOMEM: Not enough memory or address range invalid: {}",
                current_errno
            ))),
            EPERM => Err(RSealError::PermissionError(format!(
                "EPERM: Operation not permitted, possibly already sealed: {}",
                current_errno
            ))),
            _ => {
                if current_errno.0 == libc::ENOSYS {
                    Err(RSealError::SyscallNotImplemented(format!(
                        "ENOSYS: mseal syscall not implemented: {}",
                        current_errno
                    )))
                } else {
                    Err(RSealError::UnknownError(format!(
                        "Unknown error from mseal, errno: {}",
                        current_errno
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
    use std::ptr;

    #[test]
    fn test_seal_memory_basic() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size; // 1 page
            let addr = mmap(
                ptr::null_mut(),
                mem_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if addr == libc::MAP_FAILED {
                panic!("mmap failed: {}", std::io::Error::last_os_error());
            }

            let seal_result = seal_memory(addr, mem_size, 0);
            if let Err(RSealError::SyscallNotImplemented(_)) = seal_result {
                eprintln!("Skipping test_seal_memory_basic: mseal syscall not implemented");
                return;
            }
            assert!(seal_result.is_ok(), "seal_memory failed: {:?}", seal_result);

            // Attempt to change protection - should fail
            let mprotect_result = mprotect(addr, mem_size, PROT_READ);
            assert_ne!(
                mprotect_result, 0,
                "mprotect unexpectedly succeeded after mseal"
            );
            assert_eq!(
                errno::errno().0,
                EPERM,
                "Expected EPERM after mseal, got {:?}",
                errno::errno()
            );

            if munmap(addr, mem_size) != 0 {
                eprintln!(
                    "Warning: munmap failed during cleanup: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    #[test]
    fn test_seal_memory_invalid_addr() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size;
            let invalid_addr = 1 as *mut libc::c_void; // Not page-aligned and likely not mapped

            let seal_result = seal_memory(invalid_addr, mem_size, 0);
            assert!(
                seal_result.is_err(),
                "seal_memory should have failed with invalid addr"
            );
            assert!(
                matches!(seal_result, Err(RSealError::InvalidInput(_))),
                "Expected InvalidInput error"
            );
        }
    }

    #[test]
    fn test_seal_memory_not_page_aligned_addr() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size;
            let addr = mmap(
                ptr::null_mut(),
                mem_size + 1, // Allocate slightly more to get unaligned pointer
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if addr == libc::MAP_FAILED {
                panic!("mmap failed: {}", std::io::Error::last_os_error());
            }
            let unaligned_addr = addr.add(1) as *mut libc::c_void;

            let seal_result = seal_memory(unaligned_addr, mem_size, 0); // Pass unaligned addr
            assert!(
                seal_result.is_err(),
                "seal_memory should have failed with unaligned addr"
            );
            assert!(
                matches!(seal_result, Err(RSealError::InvalidInput(_))),
                "Expected InvalidInput error"
            );

            if munmap(addr, mem_size + 1) != 0 {
                eprintln!(
                    "Warning: munmap failed during cleanup: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    #[test]
    fn test_seal_memory_invalid_len() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size - 1; // Not page aligned len

            let addr = mmap(
                ptr::null_mut(),
                page_size, // Allocate page-aligned even if we use smaller length in seal
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if addr == libc::MAP_FAILED {
                panic!("mmap failed: {}", std::io::Error::last_os_error());
            }

            let seal_result = seal_memory(addr, mem_size, 0); // Pass unaligned length
            assert!(
                seal_result.is_err(),
                "seal_memory should have failed with invalid len"
            );
            assert!(
                matches!(seal_result, Err(RSealError::InvalidInput(_))),
                "Expected InvalidInput error"
            );

            if munmap(addr, page_size) != 0 {
                eprintln!(
                    "Warning: munmap failed during cleanup: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    #[test]
    fn test_seal_memory_zero_len() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size;
            let addr = mmap(
                ptr::null_mut(),
                mem_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if addr == libc::MAP_FAILED {
                panic!("mmap failed: {}", std::io::Error::last_os_error());
            }

            let seal_result = seal_memory(addr, 0, 0); // Zero length
            assert!(
                seal_result.is_err(),
                "seal_memory should have failed with zero len"
            );
            assert!(
                matches!(seal_result, Err(RSealError::InvalidInput(_))),
                "Expected InvalidInput error"
            );

            if munmap(addr, mem_size) != 0 {
                eprintln!(
                    "Warning: munmap failed during cleanup: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    #[test]
    fn test_seal_memory_null_addr() {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGE_SIZE) as usize;
            let mem_size = page_size;

            let seal_result = seal_memory(ptr::null_mut(), mem_size, 0); // Null addr
            assert!(
                seal_result.is_err(),
                "seal_memory should have failed with null addr"
            );
            assert!(
                matches!(seal_result, Err(RSealError::InvalidInput(_))),
                "Expected InvalidInput error"
            );
        }
    }
}
