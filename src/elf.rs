use crate::ctypes::{CType, Elf64_Ehdr, Elf64_Nhdr, Elf64_Phdr, PT_NOTE};
use crate::error::ParseError;
use crate::read::ReadExt;
use crate::util::trim_c_string;

#[derive(Debug)]
pub(crate) struct Elf<'d> {
    program_headers: Vec<ProgramHeader>,
    notes: Vec<Note<'d>>,
    data: &'d [u8],
}

impl<'d> Elf<'d> {
    pub fn parse(data: &'d [u8]) -> Result<Self, ParseError> {
        let header = parse_header(data)?;

        let ph_data = data.get(header.ph_offset..).ok_or_else(|| {
            format!(
                "program header table offset is out of bounds: {:#x}",
                header.ph_offset,
            )
        })?;
        let program_headers = parse_program_headers(ph_data, header.ph_count)?;

        let notes = parse_notes(&program_headers, data)?;

        Ok(Self {
            program_headers,
            notes,
            data,
        })
    }

    pub fn iter_program_headers(&self, type_: u32) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers
            .iter()
            .filter(move |ph| ph.type_ == type_)
    }

    pub fn read_segment(&self, ph: &ProgramHeader) -> Result<&'d [u8], ParseError> {
        ph.get_data(self.data)
            .ok_or_else(|| format!("program header has invalid file range: {ph:?}").into())
    }

    pub fn iter_notes<'a>(
        &'a self,
        name: &'a [u8],
        type_: u32,
    ) -> impl Iterator<Item = &'d [u8]> + 'a {
        self.notes
            .iter()
            .filter(move |n| n.name == name && n.type_ == type_)
            .map(|n| n.desc)
    }

    pub fn get_note(&self, name: &[u8], type_: u32) -> Option<&'d [u8]> {
        self.iter_notes(name, type_).next()
    }
}

fn parse_header(data: &[u8]) -> Result<Header, ParseError> {
    Elf64_Ehdr::parse(data).map(Into::into)
}

fn parse_program_headers(data: &[u8], count: usize) -> Result<Vec<ProgramHeader>, ParseError> {
    let phdrs = Elf64_Phdr::parse_n(data, count)?;
    let phs = phdrs.iter().map(Into::into).collect();
    Ok(phs)
}

fn parse_notes<'d>(phs: &[ProgramHeader], data: &'d [u8]) -> Result<Vec<Note<'d>>, ParseError> {
    let mut notes = Vec::new();
    for ph in phs {
        if ph.type_ != PT_NOTE {
            continue;
        }

        let mut note_data = ph
            .get_data(data)
            .ok_or_else(|| format!("program header has invalid file range: {ph:?}"))?;

        while !note_data.is_empty() {
            let (note, rest) = parse_note(note_data)?;
            notes.push(note);
            note_data = rest;
        }
    }

    Ok(notes)
}

fn parse_note(data: &[u8]) -> Result<(Note<'_>, &[u8]), ParseError> {
    let wrap_error = |e| format!("note: {e}");
    let padding = |n| (4 - (n % 4)) % 4;

    let nhdr = Elf64_Nhdr::parse(data)?;
    let mut data = &data[Elf64_Nhdr::SIZE..];

    let name_size = nhdr.n_namesz.to_int() as usize;
    let desc_size = nhdr.n_descsz.to_int() as usize;
    let name_padding = padding(name_size);
    let desc_padding = padding(desc_size);

    let name = data.read_slice(name_size).map_err(wrap_error)?;
    let _pad = data.read_slice(name_padding).map_err(wrap_error)?;
    let desc = data.read_slice(desc_size).map_err(wrap_error)?;
    let _pad = data.read_slice(desc_padding).map_err(wrap_error)?;

    let note = Note {
        type_: nhdr.n_type.to_int(),
        name: trim_c_string(name),
        desc,
    };
    Ok((note, data))
}

#[derive(Debug)]
struct Header {
    ph_offset: usize,
    ph_count: usize,
}

impl From<&Elf64_Ehdr> for Header {
    fn from(ehdr: &Elf64_Ehdr) -> Self {
        Self {
            ph_offset: ehdr.e_phoff.to_int() as usize,
            ph_count: ehdr.e_phnum.to_int() as usize,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramHeader {
    pub type_: u32,
    pub file_offset: usize,
    pub file_size: usize,
    pub memory_address: usize,
    pub memory_size: usize,
}

impl ProgramHeader {
    fn get_data<'d>(&self, data: &'d [u8]) -> Option<&'d [u8]> {
        let start = self.file_offset;
        let end = start + self.file_size;
        data.get(start..end)
    }
}

impl From<&Elf64_Phdr> for ProgramHeader {
    fn from(phdr: &Elf64_Phdr) -> Self {
        ProgramHeader {
            type_: phdr.p_type.to_int(),
            file_offset: phdr.p_offset.to_int() as usize,
            file_size: phdr.p_filesz.to_int() as usize,
            memory_address: phdr.p_vaddr.to_int() as usize,
            memory_size: phdr.p_memsz.to_int() as usize,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Note<'d> {
    type_: u32,
    name: &'d [u8],
    desc: &'d [u8],
}
