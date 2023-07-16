use core::fmt;

use crate::ctypes::{
    elf_gregset_t, elf_prpsinfo, elf_prstatus, CType, NT_FILE, NT_PRPSINFO, NT_PRSTATUS, PT_LOAD,
};
use crate::elf::Elf;
use crate::error::ParseError;
use crate::read::ReadExt;
use crate::util::trim_c_string;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Core<'d> {
    pub segments: Vec<Segment<'d>>,
    pub process: ProcessInfo<'d>,
    pub threads: Vec<ThreadInfo>,
    pub file_map: Vec<FileMapping<'d>>,
}

impl<'d> Core<'d> {
    pub fn parse(data: &'d [u8]) -> Result<Self, ParseError> {
        let elf = Elf::parse(data)?;

        Ok(Self {
            segments: extract_segments(&elf)?,
            process: extract_process_info(&elf)?,
            threads: extract_thread_infos(&elf)?,
            file_map: extract_file_map(&elf)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Segment<'d> {
    pub vm_start: usize,
    pub vm_end: usize,
    pub data: &'d [u8],
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("vm_start", &format_args!("{:#x}", self.vm_start))
            .field("vm_end", &format_args!("{:#x}", self.vm_end))
            .field("data", &format_args!("…"))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessInfo<'d> {
    pub state: i8,
    pub state_name: char,
    pub zombie: bool,
    pub nice: i8,
    pub flags: u64,
    pub uid: i32,
    pub gid: i32,
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub sid: i32,
    pub file_name: &'d [u8],
    pub command: &'d [u8],
}

impl fmt::Debug for ProcessInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessInfo")
            .field("state", &self.state)
            .field("state_name", &self.state_name)
            .field("zombie", &self.zombie)
            .field("nice", &self.nice)
            .field("flags", &format_args!("{:#x}", self.flags))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .field("pgrp", &self.pgrp)
            .field("sid", &self.sid)
            .field("file_name", &String::from_utf8_lossy(self.file_name))
            .field("command", &String::from_utf8_lossy(self.command))
            .finish()
    }
}

impl<'d> From<&'d elf_prpsinfo> for ProcessInfo<'d> {
    fn from(prpsinfo: &'d elf_prpsinfo) -> Self {
        Self {
            state: prpsinfo.pr_state,
            state_name: prpsinfo.pr_sname.into(),
            zombie: prpsinfo.pr_zomb == 1,
            nice: prpsinfo.pr_nice,
            flags: prpsinfo.pr_flag.to_int(),
            uid: prpsinfo.pr_uid.to_int(),
            gid: prpsinfo.pr_gid.to_int(),
            pid: prpsinfo.pr_pid.to_int(),
            ppid: prpsinfo.pr_ppid.to_int(),
            pgrp: prpsinfo.pr_pgrp.to_int(),
            sid: prpsinfo.pr_sid.to_int(),
            file_name: trim_c_string(&prpsinfo.pr_fname),
            command: trim_c_string(&prpsinfo.pr_psargs),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Debug)]
pub struct ThreadInfo {
    pub pid: i32,
    pub registers: Registers,
}

impl From<&elf_prstatus> for ThreadInfo {
    fn from(prstatus: &elf_prstatus) -> Self {
        Self {
            pid: prstatus.common.pr_pid.to_int(),
            registers: (&prstatus.pr_reg).into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ds: u64,
    pub ss: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

impl fmt::Debug for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registers")
            .field("rax", &format_args!("{:#018x}", self.rax))
            .field("rbx", &format_args!("{:#018x}", self.rbx))
            .field("rcx", &format_args!("{:#018x}", self.rcx))
            .field("rdx", &format_args!("{:#018x}", self.rdx))
            .field("rbp", &format_args!("{:#018x}", self.rbp))
            .field("rsp", &format_args!("{:#018x}", self.rsp))
            .field("rsi", &format_args!("{:#018x}", self.rsi))
            .field("rdi", &format_args!("{:#018x}", self.rdi))
            .field("r8", &format_args!("{:#018x}", self.r8))
            .field("r9", &format_args!("{:#018x}", self.r9))
            .field("r10", &format_args!("{:#018x}", self.r10))
            .field("r11", &format_args!("{:#018x}", self.r11))
            .field("r12", &format_args!("{:#018x}", self.r12))
            .field("r13", &format_args!("{:#018x}", self.r13))
            .field("r14", &format_args!("{:#018x}", self.r14))
            .field("r15", &format_args!("{:#018x}", self.r15))
            .field("rip", &format_args!("{:#018x}", self.rip))
            .field("rflags", &format_args!("{:#018x}", self.rflags))
            .field("cs", &format_args!("{:#018x}", self.cs))
            .field("ds", &format_args!("{:#018x}", self.ds))
            .field("ss", &format_args!("{:#018x}", self.ss))
            .field("es", &format_args!("{:#018x}", self.es))
            .field("fs", &format_args!("{:#018x}", self.fs))
            .field("gs", &format_args!("{:#018x}", self.gs))
            .field("fs_base", &format_args!("{:#018x}", self.fs_base))
            .field("gs_base", &format_args!("{:#018x}", self.gs_base))
            .finish()
    }
}

impl From<&elf_gregset_t> for Registers {
    fn from(gregset: &elf_gregset_t) -> Self {
        Self {
            rax: gregset.ax.to_int(),
            rbx: gregset.bx.to_int(),
            rcx: gregset.cx.to_int(),
            rdx: gregset.dx.to_int(),
            rbp: gregset.bp.to_int(),
            rsp: gregset.sp.to_int(),
            rsi: gregset.si.to_int(),
            rdi: gregset.di.to_int(),
            r8: gregset.r8.to_int(),
            r9: gregset.r9.to_int(),
            r10: gregset.r10.to_int(),
            r11: gregset.r11.to_int(),
            r12: gregset.r12.to_int(),
            r13: gregset.r13.to_int(),
            r14: gregset.r14.to_int(),
            r15: gregset.r15.to_int(),
            rip: gregset.ip.to_int(),
            rflags: gregset.flags.to_int(),
            cs: gregset.cs.to_int(),
            ds: gregset.ds.to_int(),
            ss: gregset.ss.to_int(),
            es: gregset.es.to_int(),
            fs: gregset.fs.to_int(),
            gs: gregset.gs.to_int(),
            fs_base: gregset.fs_base.to_int(),
            gs_base: gregset.gs_base.to_int(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileMapping<'d> {
    pub vm_start: usize,
    pub vm_end: usize,
    pub file_offset: u64,
    pub file_path: &'d [u8],
}

impl fmt::Debug for FileMapping<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileMapping")
            .field("vm_start", &format_args!("{:#x}", self.vm_start))
            .field("vm_end", &format_args!("{:#x}", self.vm_end))
            .field("file_offset", &format_args!("{:#x}", self.file_offset))
            .field("file_path", &String::from_utf8_lossy(self.file_path))
            .finish()
    }
}

fn extract_segments<'d>(elf: &Elf<'d>) -> Result<Vec<Segment<'d>>, ParseError> {
    let mut segments = Vec::new();
    for ph in elf.iter_program_headers(PT_LOAD) {
        if ph.memory_size != ph.file_size {
            Err(format!(
                "segment file size ({:#x}) differs from memory size ({:#x})",
                ph.file_size, ph.memory_size
            ))?;
        }

        let vm_start = ph.memory_address;
        let vm_end = vm_start + ph.memory_size;
        let data = elf.read_segment(ph)?;

        segments.push(Segment {
            vm_start,
            vm_end,
            data,
        });
    }

    Ok(segments)
}

fn extract_process_info<'d>(elf: &Elf<'d>) -> Result<ProcessInfo<'d>, ParseError> {
    let data = elf
        .get_note(b"CORE", NT_PRPSINFO)
        .ok_or_else(|| "missing note: CORE/NT_PRPSINFO".to_string())?;

    elf_prpsinfo::parse(data).map(Into::into)
}

fn extract_thread_infos(elf: &Elf<'_>) -> Result<Vec<ThreadInfo>, ParseError> {
    elf.iter_notes(b"CORE", NT_PRSTATUS)
        .map(|data| elf_prstatus::parse(data).map(Into::into))
        .collect()
}

fn extract_file_map<'d>(elf: &Elf<'d>) -> Result<Vec<FileMapping<'d>>, ParseError> {
    let wrap_error = |e| format!("NT_FILE note: {e}");

    let mut data = elf
        .get_note(b"CORE", NT_FILE)
        .ok_or_else(|| "missing note: CORE/NT_FILE".to_string())?;

    let count = data.read_u64().map_err(wrap_error)?;
    let page_size = data.read_u64().map_err(wrap_error)?;

    let mut mappings = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let vm_start = data.read_u64().map_err(wrap_error)?;
        let vm_end = data.read_u64().map_err(wrap_error)?;
        let page_idx = data.read_u64().map_err(wrap_error)?;

        mappings.push(FileMapping {
            vm_start: vm_start as usize,
            vm_end: vm_end as usize,
            file_offset: page_idx * page_size,
            file_path: &[],
        });
    }

    let mut paths = data.split(|c| *c == b'\0');
    for map in &mut mappings {
        let path = paths
            .next()
            .ok_or_else(|| "NT_FILE note contains too few paths".to_string())?;
        map.file_path = path;
    }

    Ok(mappings)
}
