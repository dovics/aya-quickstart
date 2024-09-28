#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[kprobe]
pub fn kprobe_unlinkat(ctx: ProbeContext) -> u32 {
    match try_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_unlinkat(ctx: ProbeContext) -> Result<u32, i64> {
    let path_ptr = ctx.arg(1).ok_or(1)?;

    let pid = bpf_get_current_pid_tgid() >> 32;
    let mut path_buf = [0u8; 256];

    let res = unsafe { bpf_probe_read_kernel_str_bytes(path_ptr, &mut path_buf)? };

    let path_str = unsafe { core::str::from_utf8_unchecked(res) };

    info!(
        &ctx,
        "KPROBE ENTRY pid = {},  filename = {}\n", pid, path_str
    );

    Ok(0)
}

#[kretprobe]
pub fn kretprobe_unlinkat(ctx: ProbeContext) -> u32 {
    match try_unlinkat_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_unlinkat_ret(ctx: ProbeContext) -> Result<u32, i64> {
    let ret: i64 = ctx.ret().ok_or(1)?;

    let pid = bpf_get_current_pid_tgid() >> 32;

    info!(&ctx, "KPROBE EXIT: pid = {}, ret = {}\n", pid, ret);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
