#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, gen::bpf_probe_read_kernel}, 
    macros::{kprobe, kretprobe}, 
    programs::ProbeContext};
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
    let _: u64 = ctx.arg(0).ok_or(1)?;
    let path_ptr: u64 = ctx.arg(1).ok_or(1)?;
    
    let pid = bpf_get_current_pid_tgid() >> 32;
    let mut path_buf = [0u8; 256];
    let path_str;
    let mut i = 0;
    unsafe {
        while i < 256 {
            let mut byte: u8 = 0;
            let res = bpf_probe_read_kernel(&mut byte as *mut u8 as *mut _, 1, (path_ptr + i as u64) as *const _);
            if res < 0 {
                return Err(res);
            }
            if byte == 0 {
                break;
            }

            path_buf[i] = byte;
            i += 1;
        }
        path_str =  core::str::from_utf8_unchecked(&path_buf[..i]);
    };
    
    info!(&ctx, "KPROBE ENTRY pid = {}, path_ptr = {}, filename = {}\n", pid, path_ptr, path_str);

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

