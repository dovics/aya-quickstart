#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, gen::bpf_probe_read_user_str}, 
    macros::uretprobe, 
    programs::ProbeContext
};
use aya_log_ebpf::info;

#[uretprobe]
pub fn uprobe_readline(ctx: ProbeContext) -> u32 {
    match try_readline_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_readline_ret(ctx: ProbeContext) -> Result<u32, i64> {
    let ret = ctx.ret().ok_or(1)?;
    let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm()?;
    let mut str_buf = [0u8; 256];
    let res = unsafe { bpf_probe_read_user_str(&mut str_buf as *mut u8 as *mut _, 256, ret) };
    if res < 0 {
        return Err(res);
    }

    let result_str = unsafe { core::str::from_utf8_unchecked(&str_buf[..res as usize]) };
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..res as usize]) };
    info!(&ctx, "PID {} ({}) read: {}.\n", pid, comm_str, result_str);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}