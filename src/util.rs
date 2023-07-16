pub(crate) fn trim_c_string(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or(&[])
}
