#[macro_export]
macro_rules! filed_of {
    ($ptr:ident ,$ty:ty, $field:ident) => {{
        let filed_offset = offset_of!($ty, $field);
        unsafe { bpf_probe_read_kernel(($ptr as usize + filed_offset) as *const _) }?
    }};
}
