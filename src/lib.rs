#![deny(missing_debug_implementations)]
/* TODO #![deny(missing_docs)] */

mod core;
mod ctypes;
mod elf;
mod error;
mod read;
mod util;

const _FORCE_64BIT: () = assert!(
    usize::BITS == u64::BITS,
    "this library only supports 64-bit targets"
);

pub use crate::core::{Core, FileMapping, ProcessInfo, Registers, Segment, ThreadInfo};
pub use crate::error::ParseError;
