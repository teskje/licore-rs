pub(crate) type Result<T> = std::result::Result<T, &'static str>;

pub(crate) trait ReadExt<'d> {
    fn read_slice(&mut self, n: usize) -> Result<&'d [u8]>;
    fn read_array<const N: usize>(&mut self) -> Result<&'d [u8; N]>;
    fn read_u8(&mut self) -> Result<u8>;
    fn read_i8(&mut self) -> Result<i8>;
    fn read_u16(&mut self) -> Result<u16>;
    fn read_i16(&mut self) -> Result<i16>;
    fn read_u32(&mut self) -> Result<u32>;
    fn read_i32(&mut self) -> Result<i32>;
    fn read_u64(&mut self) -> Result<u64>;
    fn read_i64(&mut self) -> Result<i64>;
}

impl<'d> ReadExt<'d> for &'d [u8] {
    fn read_slice(&mut self, n: usize) -> Result<&'d [u8]> {
        if self.len() < n {
            return Err("not enough data");
        }

        let (bytes, rest) = self.split_at(n);
        *self = rest;
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<&'d [u8; N]> {
        self.read_slice(N).map(|s| s.try_into().unwrap())
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.read_array().map(|b| u8::from_le_bytes(*b))
    }

    fn read_i8(&mut self) -> Result<i8> {
        self.read_array().map(|b| i8::from_le_bytes(*b))
    }

    fn read_u16(&mut self) -> Result<u16> {
        self.read_array().map(|b| u16::from_le_bytes(*b))
    }

    fn read_i16(&mut self) -> Result<i16> {
        self.read_array().map(|b| i16::from_le_bytes(*b))
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.read_array().map(|b| u32::from_le_bytes(*b))
    }

    fn read_i32(&mut self) -> Result<i32> {
        self.read_array().map(|b| i32::from_le_bytes(*b))
    }

    fn read_u64(&mut self) -> Result<u64> {
        self.read_array().map(|b| u64::from_le_bytes(*b))
    }

    fn read_i64(&mut self) -> Result<i64> {
        self.read_array().map(|b| i64::from_le_bytes(*b))
    }
}
