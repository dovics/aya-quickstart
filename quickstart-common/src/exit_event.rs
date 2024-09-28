
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub ppid: u32,
    pub exit_code: i32,
    pub duration: u64,
    pub comm: [u8; 16],
}

