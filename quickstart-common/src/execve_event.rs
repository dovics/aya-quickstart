
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub ret: i64,
    pub is_exit: bool,
    pub comm: [u8; 16],
}

