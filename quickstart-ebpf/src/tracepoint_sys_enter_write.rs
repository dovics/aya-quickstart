#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext
};
use aya_log_ebpf::info;

const FILTED_PID: u64 = 0;
#[tracepoint(name = "sys_enter_write", category = "syscalls")]
pub fn enter_write(ctx: TracePointContext) -> u32 {
    let pid = bpf_get_current_pid_tgid();

    if pid == FILTED_PID {
        return 0
    }

    info!(&ctx, "BPF triggered sys_enter_write from PID {}.\n", pid);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}