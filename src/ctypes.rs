#![allow(non_camel_case_types)]

use std::fmt::{Debug, Display};
use std::mem;

use structview::{i16_le, i32_le, i64_le, u16_le, u32_le, u64_le, View};

use crate::error::ParseError;

pub(crate) use constants::*;

pub(crate) trait CType: View {
    const NAME: &'static str;
    const SIZE: usize = mem::size_of::<Self>();

    fn parse(data: &[u8]) -> Result<&Self, ParseError> {
        let obj = Self::view(data).map_err(Self::wrap_error)?;
        obj.verify().map_err(Self::wrap_error)?;

        Ok(obj)
    }

    fn parse_many(data: &[u8]) -> Result<&[Self], ParseError> {
        let objs = Self::view_slice(data).map_err(Self::wrap_error)?;
        for obj in objs {
            obj.verify().map_err(Self::wrap_error)?;
        }

        Ok(objs)
    }

    fn parse_n(data: &[u8], count: usize) -> Result<&[Self], ParseError> {
        let size = Self::SIZE * count;
        let data = data
            .get(..size)
            .ok_or_else(|| Self::wrap_error("not enough data"))?;

        Self::parse_many(data)
    }

    fn wrap_error<E: Display>(error: E) -> String {
        format!("{}: {}", Self::NAME, error)
    }

    fn verify(&self) -> Result<(), String> {
        Ok(())
    }
}

fn expect<T>(name: &str, got: T, expected: T) -> Result<(), String>
where
    T: Eq + Debug,
{
    if got == expected {
        Ok(())
    } else {
        let msg = format!("invalid {name} value: got {got:?}, expected: {expected:?}");
        Err(msg)
    }
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct Elf64_Ehdr {
    /// ELF "magic number".
    pub e_ident: [u8; 16],
    pub e_type: u16_le,
    pub e_machine: u16_le,
    pub e_version: u32_le,
    /// Entry point virtual address.
    pub e_entry: u64_le,
    /// Program header table file offset.
    pub e_phoff: u64_le,
    /// Section header table file offset.
    pub e_shoff: u64_le,
    pub e_flags: u32_le,
    pub e_ehsize: u16_le,
    pub e_phentsize: u16_le,
    pub e_phnum: u16_le,
    pub e_shentsize: u16_le,
    pub e_shnum: u16_le,
    pub e_shstrndx: u16_le,
}

impl CType for Elf64_Ehdr {
    const NAME: &'static str = "Elf64_Ehdr";

    fn verify(&self) -> Result<(), String> {
        expect("e_ident.magic", &self.e_ident[..4], b"\x7fELF")?;
        expect("e_ident.class", self.e_ident[4], ELFCLASS64)?;
        expect("e_ident.data", self.e_ident[5], ELFDATA2LSB)?;
        expect("e_ident.version", self.e_ident[6], EV_CURRENT)?;
        expect("e_ident.osabi", self.e_ident[7], ELFOSABI_SYSV)?;
        expect("e_type", self.e_type.to_int(), ET_CORE)?;
        expect("e_machine", self.e_machine.to_int(), EM_X86_64)?;
        expect("e_version", self.e_version.to_int(), EV_CURRENT.into())?;
        expect("e_ehsize", self.e_ehsize.to_int(), 64)?;
        expect("e_phentsize", self.e_phentsize.to_int(), 56)?;
        expect("e_shentsize", self.e_shentsize.to_int(), 64)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct Elf64_Phdr {
    pub p_type: u32_le,
    pub p_flags: u32_le,
    /// Segment file offset.
    pub p_offset: u64_le,
    /// Segment virtual address.
    pub p_vaddr: u64_le,
    /// Segment physical address.
    pub p_paddr: u64_le,
    /// Segment size in file.
    pub p_filesz: u64_le,
    /// Segment size in memory.
    pub p_memsz: u64_le,
    /// Segment alignment, file & memory.
    pub p_align: u64_le,
}

impl CType for Elf64_Phdr {
    const NAME: &'static str = "Elf64_Phdr";

    fn verify(&self) -> Result<(), String> {
        let p_vaddr = self.p_vaddr.to_int();
        let p_paddr = self.p_paddr.to_int();

        if p_vaddr % self.p_align.to_int() != 0 {
            Err(format!("unaligned p_vaddr value: {p_vaddr:#x}"))
        } else if p_paddr % self.p_align.to_int() != 0 {
            Err(format!("unaligned p_paddr value: {p_paddr:#x}"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct Elf64_Nhdr {
    pub n_namesz: u32_le,
    pub n_descsz: u32_le,
    pub n_type: u32_le,
}

impl CType for Elf64_Nhdr {
    const NAME: &'static str = "Elf64_Nhdr";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct elf_prpsinfo {
    pub pr_state: i8,
    pub pr_sname: u8,
    pub pr_zomb: i8,
    pub pr_nice: i8,
    _pad1: [u8; 4],
    pub pr_flag: u64_le,
    pub pr_uid: i32_le,
    pub pr_gid: i32_le,
    pub pr_pid: i32_le,
    pub pr_ppid: i32_le,
    pub pr_pgrp: i32_le,
    pub pr_sid: i32_le,
    pub pr_fname: [u8; 16],
    pub pr_psargs: [u8; 80],
}

impl CType for elf_prpsinfo {
    const NAME: &'static str = "elf_prpsinfo";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct elf_prstatus {
    pub common: elf_prstatus_common,
    pub pr_reg: elf_gregset_t,
    pub pr_fpvalid: i32_le,
}

impl CType for elf_prstatus {
    const NAME: &'static str = "elf_prstatus";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct elf_prstatus_common {
    pub pr_info: elf_siginfo,
    pub pr_cursig: i16_le,
    _pad1: [u8; 2],
    pub pr_sigpend: u64_le,
    pub pr_sighold: u64_le,
    pub pr_pid: i32_le,
    pub pr_ppid: i32_le,
    pub pr_pgrp: i32_le,
    pub pr_sid: i32_le,
    pub pr_utime: __kernel_old_timeval,
    pub pr_stime: __kernel_old_timeval,
    pub pr_cutime: __kernel_old_timeval,
    pub pr_cstime: __kernel_old_timeval,
}

impl CType for elf_prstatus_common {
    const NAME: &'static str = "elf_prstatus_common";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct elf_siginfo {
    pub si_signo: i32_le,
    pub si_code: i32_le,
    pub si_errno: i32_le,
}

impl CType for elf_siginfo {
    const NAME: &'static str = "elf_siginfo";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct elf_gregset_t {
    pub r15: u64_le,
    pub r14: u64_le,
    pub r13: u64_le,
    pub r12: u64_le,
    pub bp: u64_le,
    pub bx: u64_le,
    pub r11: u64_le,
    pub r10: u64_le,
    pub r9: u64_le,
    pub r8: u64_le,
    pub ax: u64_le,
    pub cx: u64_le,
    pub dx: u64_le,
    pub si: u64_le,
    pub di: u64_le,
    pub orig_ax: u64_le,
    pub ip: u64_le,
    pub cs: u64_le,
    pub flags: u64_le,
    pub sp: u64_le,
    pub ss: u64_le,
    pub fs_base: u64_le,
    pub gs_base: u64_le,
    pub ds: u64_le,
    pub es: u64_le,
    pub fs: u64_le,
    pub gs: u64_le,
}

impl CType for elf_gregset_t {
    const NAME: &'static str = "elf_gregset_t";
}

#[derive(Clone, Copy, Debug, View)]
#[repr(C)]
pub(crate) struct __kernel_old_timeval {
    pub tv_sec: i64_le,
    pub tv_usec: i64_le,
}

impl CType for __kernel_old_timeval {
    const NAME: &'static str = "__kernel_old_timeval";
}

mod constants {
    /// 64-bit file class.
    pub const ELFCLASS64: u8 = 2;

    /// Little-endian data encoding.
    pub const ELFDATA2LSB: u8 = 1;

    /// Current file format version.
    pub const EV_CURRENT: u8 = 1;

    /// System V ABI.
    pub const ELFOSABI_SYSV: u8 = 0;

    /// Core file type.
    pub const ET_CORE: u16 = 4;

    /// AMD x86-64 machine architecture.
    pub const EM_X86_64: u16 = 62;

    /// Loadable segment.
    pub const PT_LOAD: u32 = 1;
    /// Note sections.
    pub const PT_NOTE: u32 = 4;

    /// Thread status.
    pub const NT_PRSTATUS: u32 = 1;
    /// Process info.
    pub const NT_PRPSINFO: u32 = 3;
    /// File map.
    pub const NT_FILE: u32 = 0x4649_4c45;
}
