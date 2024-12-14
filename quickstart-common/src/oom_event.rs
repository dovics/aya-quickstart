
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub fpid: u32,
    pub tpid: u32,
    pub pages: u64,
    pub fcomm: [u8; 16],
    pub tcomm: [u8; 16],
}