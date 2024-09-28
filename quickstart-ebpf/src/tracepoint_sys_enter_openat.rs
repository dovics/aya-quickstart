#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map}, 
    programs::TracePointContext,
    helpers::bpf_get_current_pid_tgid,
    maps::Array,
};
use aya_log_ebpf::info;

#[map]
static LIST: Array<u64> = Array::<u64>::with_max_entries(1024, 0);

#[tracepoint]
pub fn enter_openat(ctx: TracePointContext) -> u32 {
    let pid = bpf_get_current_pid_tgid();

    let target = LIST.get(0);
    if target.is_some() && pid != *target.unwrap() {
        return 0
    }
    
    info!(&ctx, "BPF triggered sys_enter_openat from PID {}.\n", pid);

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}