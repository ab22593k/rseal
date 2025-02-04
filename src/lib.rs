pub mod errors;
mod rseal;

use std::{
    alloc::{alloc, Layout},
    fmt,
    marker::PhantomData,
    ptr::NonNull,
};

use errors::RSealMemError;
use rseal::seal_memory;

/// A buffer type that stores data in sealed memory that cannot be accessed except through the provided methods
pub struct RSealBuff {
    region: RSealMemory<u8>,
}

impl RSealBuff {
    /// Creates a new sealed buffer with the given size in bytes
    ///
    /// # Arguments
    /// * `size` - The size of the buffer in bytes
    pub fn new(size: usize) -> Result<Self, RSealMemError> {
        Ok(Self {
            region: RSealMemory::new(size)?,
        })
    }

    /// Writes data into the buffer
    ///
    /// # Arguments
    /// * `data` - The slice of bytes to write into the buffer
    ///
    /// # Returns
    /// The number of bytes successfully written (will be the minimum of the buffer size and data length)
    pub fn write(&mut self, data: &[u8]) -> usize {
        let buf = unsafe { self.region.as_mut() };
        let len = std::cmp::min(buf.len(), data.len());
        buf[..len].copy_from_slice(&data[..len]);
        len
    }

    /// Reads the current contents of the buffer
    ///
    /// # Returns
    /// A slice containing the buffer contents
    pub fn read(&self) -> &[u8] {
        unsafe { self.region.as_ref() }
    }
}

/// A wrapper around a memory region that has been sealed.
/// This type ensures the memory is properly managed and can't be freed
/// while sealed.
struct RSealMemory<T> {
    ptr: NonNull<T>,
    layout: Layout,
    _phantom: PhantomData<T>,
}

impl fmt::Display for RSealMemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationError => write!(f, "Allocation error"),
            Self::SealError(e) => write!(f, "Sealing error: {}", e),
            Self::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
        }
    }
}

impl<T> RSealMemory<T> {
    /// Creates a new sealed memory region that can hold `count` instances of T.
    ///
    /// # Safety
    ///
    /// This function is safe to call, but the resulting memory is uninitialized.
    /// The caller must initialize the memory before reading from it.
    fn new(count: usize) -> Result<Self, RSealMemError> {
        // Get the system page size for memory alignment
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as usize;

        // Calculate total size needed for count items
        let item_size = std::mem::size_of::<T>();
        let requested_size = item_size * count;

        // Round up to nearest page size boundary for alignment
        // Use bitwise math: (size + page_size - 1) & ~(page_size - 1)
        let total_size = (requested_size + page_size - 1) & !(page_size - 1);

        // Create memory layout with proper size and alignment
        let layout = Layout::from_size_align(total_size, page_size)
            .map_err(|_| RSealMemError::InvalidParameters("Invalid size or alignment"))?;

        // Allocate memory using system allocator
        // Safety: Layout is guaranteed valid by from_size_align check above
        let ptr = unsafe { NonNull::new(alloc(layout) as *mut T) }
            .ok_or(RSealMemError::AllocationError)?;

        // Seal the allocated memory to prevent access
        // Safety: ptr and size are valid as checked above
        unsafe {
            seal_memory(ptr.as_ptr() as *mut libc::c_void, total_size, 0)
                .map_err(RSealMemError::SealError)?;
        }

        // Return successful sealed memory allocation
        Ok(Self {
            ptr,
            layout,
            _phantom: PhantomData,
        })
    }

    fn len(&self) -> usize {
        self.layout.size() / std::mem::size_of::<T>()
    }

    /// Returns a reference to the sealed memory region.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory has been properly initialized
    /// before reading from it.
    unsafe fn as_ref(&self) -> &[T] {
        std::slice::from_raw_parts(self.ptr.as_ptr(), self.len())
    }

    /// Returns a mutable reference to the sealed memory region.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory has been properly initialized
    /// before reading from it, and that no other references to this memory exist.
    unsafe fn as_mut(&mut self) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len())
    }
}

impl<T> Drop for RSealMemory<T> {
    fn drop(&mut self) {
        eprintln!("Warning: Dropping sealed memory region - this memory will remain allocated until process termination");
    }
}

#[cfg(test)]
mod tests {
    use errors::RSealError;

    use super::*;

    #[test]
    fn test_sealed_buffer() {
        let result = RSealBuff::new(4096);
        if let Err(RSealMemError::SealError(RSealError::SyscallNotImplemented(_))) = result {
            eprintln!("Skipping test_sealed_buffer: mseal syscall not implemented");
            return;
        }
        let mut buffer = result.unwrap();
        let data = b"Hello, world!";

        let written = buffer.write(data);
        assert_eq!(written, data.len());
        assert_eq!(&buffer.read()[..written], data);
    }

    #[test]
    fn test_sealed_memory() {
        let result = RSealMemory::<u32>::new(1024);
        if let Err(RSealMemError::SealError(RSealError::SyscallNotImplemented(_))) = result {
            eprintln!("Skipping test_sealed_memory: mseal syscall not implemented");
            return;
        }
        assert!(result.is_ok());
    }
}
