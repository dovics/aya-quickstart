#![no_std]
#![no_main]
mod utils;
mod vmlinux;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};
use core::mem::offset_of;

use aya_log_ebpf::{debug, warn};
use quickstart_common::connect_event::{IPv4Data, IPv4FlowKey};
use vmlinux::{sock, sock_common};

#[map]
static CURRSOCK: HashMap<u32, usize> = HashMap::with_max_entries(1024, 0);

#[map]
static IPV4_COUNT: HashMap<IPv4FlowKey, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static IPV4_EVENT: PerfEventArray<IPv4Data> = PerfEventArray::with_max_entries(1024, 0);

fn ipv4_count_increase(key: &IPv4FlowKey) -> Result<(), i64> {
    let value = *unsafe { IPV4_COUNT.get(key) }.ok_or(1)?;
    IPV4_COUNT.remove(key)?;
    IPV4_COUNT.insert(key, &(value + 1), 0)?;
    Ok(())
}

#[kprobe]
fn kprobe_tcp_connect_entry(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let sk_ptr: usize = ctx.arg(0).ok_or(1)?;

    let tid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // let uid = bpf_get_current_uid_gid();

    debug!(&ctx, "entry tid {}", tid);
    CURRSOCK.insert(&tid, &sk_ptr, 0)?;
    Ok(0)
}

#[kretprobe]
fn kretprobe_tcp_connect_return(ctx: ProbeContext) -> u32 {
    match try_tcp_connect_return(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tcp_connect_return(ctx: ProbeContext) -> Result<u32, i64> {
    let tid = (bpf_get_current_pid_tgid() >> 32) as u32;
    debug!(&ctx, "return tid {}", tid);
    let sk_ptr = unsafe { *CURRSOCK.get(&tid).ok_or(1)? as *const sock };

    debug!(&ctx, "get socket success", tid);
    let ret: usize = ctx.ret().ok_or(1)?;
    if ret != 0 {
        CURRSOCK.remove(&tid)?;
        debug!(&ctx, "connect failed {}, return {}", tid, ret);
        return Ok(0);
    }

    let skc: sock_common = filed_of!(sk_ptr, sock, __sk_common);

    let lport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_num };
    let dport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_dport };

    let saddr = unsafe { skc.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr };
    let daddr = unsafe { skc.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };

    match ipv4_count_increase(&IPv4FlowKey {
        saddr,
        daddr,
        dport,
    }) {
        Ok(_) => {
            debug!(&ctx, "increase_ipv4_count success");
        }
        Err(_) => {
            warn!(&ctx, "increase_ipv4_count failed");
        }
    }

    IPV4_EVENT.output(
        &ctx,
        &IPv4Data {
            ts_us: (unsafe { bpf_ktime_get_ns() } / 1000) as u64,
            pid: tid,
            uid: (bpf_get_current_uid_gid() >> 32) as u32,
            saddr,
            daddr,
            lport,
            dport,
            ret: ret as i64,
            ip: 4 as u64,
            comm: { bpf_get_current_comm()? },
        },
        0,
    );
    debug!(&ctx, "output event success");

    CURRSOCK.remove(&tid)?;
    debug!(&ctx, "return success", tid);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
