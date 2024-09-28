#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

struct Event {
    pid: u32,
    tpid: u64,
    sig: u64,
    ret: i64,
    comm: [u8; 16],
}

#[map]
static EVENTS_MAP: HashMap<u32, Event> = HashMap::with_max_entries(1024, 0);

#[tracepoint(name = "sys_enter_kill", category = "syscalls")]
pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    match try_enter_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_enter_kill(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let tpid = unsafe { ctx.read_at::<u64>(16)? };
    let sig = unsafe { ctx.read_at(24)? };
    let comm = bpf_get_current_comm()?;
    let event = Event {
        pid,
        tpid,
        sig,
        ret: -1,
        comm,
    };

    EVENTS_MAP.insert(&pid, &event, 0)?;
    Ok(0)
}

#[tracepoint(name = "sys_exit_kill", category = "syscalls")]
pub fn sys_exit_kill(ctx: TracePointContext) -> u32 {
    match try_exit_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_exit_kill(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let event_ptr = EVENTS_MAP.get_ptr_mut(&pid).ok_or(1)?;

    let event = unsafe { &mut *event_ptr };
    event.ret = unsafe { ctx.read_at(16) }?;

    let comm_str = unsafe { core::str::from_utf8_unchecked(&event.comm) };

    if event.sig != 0 {
        info!(
            &ctx,
            "PID {} ({}) sent signal {} to PID {}, ret: {}",
            event.pid,
            comm_str,
            event.sig,
            event.tpid,
            event.ret
        );
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
