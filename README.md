# RSeal

A Rust library for memory sealing operations using Linux's mseal syscall.

## Overview

RSeal provides a safe Rust interface for sealing memory regions, preventing them from being modified after initialization. This is useful for security-sensitive applications that need to protect critical data from tampering.

## Features

- Safe wrapper around the Linux mseal syscall
- Page-aligned memory allocation and sealing
- Comprehensive error handling
- Memory safety guarantees through Rust's ownership system
- Extensive test coverage

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rseal = "0.1.0"
```

## Quick Start

```rust
use rseal::SealedBuffer;

fn main() -> Result<(), rseal::errors::RSealMemError> {
    // Create a new sealed buffer with 4KB capacity
    let mut buffer = SealedBuffer::new(4096)?;

    // Write data to the buffer (before sealing)
    let data = b"Sensitive data";
    buffer.write(data);

    // After this point, the memory cannot be modified
    let sealed_data = buffer.read();
    assert_eq!(&sealed_data[..data.len()], data);

    Ok(())
}
```

## API Documentation

### Key Types

- `SealedMemory<T>`: Low-level wrapper for sealed memory regions
- `SealedBuffer`: High-level wrapper for byte-oriented sealed memory
- `RSealError`: Error types for sealing operations
- `RSealMemError`: Memory-specific error types

### Safety

Memory sealing is irreversible - sealed memory regions cannot be freed until process termination. Use this library judiciously and be aware of the memory usage implications.

## Technical Details

RSeal uses the Linux `mseal` syscall to prevent further modifications to memory regions. Key features include:

- Page-aligned memory allocation
- Comprehensive error checking
- Safe Rust abstractions over unsafe system calls
- Automatic handling of memory alignment requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Areas for improvement include:

- Support for other operating systems
- Additional memory protection features
- Performance optimizations
- Documentation improvements

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Platform Support

Currently supports Linux only. The `mseal` syscall is required.
