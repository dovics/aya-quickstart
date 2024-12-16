#[derive(Debug, Clone, Copy)]
pub struct IPv4Data {
    pub ts_us: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub ip: u64,
    pub lport: u16,
    pub dport: u16,
    pub ret: i64,
    pub comm: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
pub struct IPv6Data {
    pub ts_us: u64,
    pub pid: u32,
    pub uid: u32,
    pub saddr: u128,
    pub daddr: u128,
    pub ip: u64,
    pub lport: u16,
    pub dport: u16,
    pub ret: i64,
    pub comm: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
pub struct IPv4FlowKey {
    pub saddr: u32,
    pub daddr: u32,
    pub dport: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct IPv6FlowKey {
    pub saddr: u128,
    pub daddr: u128,
    pub u16: u16,
}
