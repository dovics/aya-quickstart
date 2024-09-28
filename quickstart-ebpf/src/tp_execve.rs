#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_get_current_uid_gid,
        bpf_perf_event_output, gen::bpf_probe_read_str,
    },
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext, EbpfContext,
};
use quickstart_common::execve_event::Event;

#[map]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let task = unsafe { bpf_get_current_task_btf() as *const vmlinux::task_struct };
    let real_parent = unsafe { (*task).real_parent };
    let parent_task_struct = real_parent as *const vmlinux::task_struct;
    let ppid = unsafe { (*parent_task_struct).pid };
    let mut cmd_buf = [0u8; 16];
    let cmd_ptr = unsafe { ctx.read_at::<*const u8>(16)? };

    let res =
        unsafe { bpf_probe_read_str(cmd_buf.as_mut_ptr() as *mut _, 16, cmd_ptr as *const _) };
    if res < 0 {
        return Err(res);
    }

    let event = Event {
        pid,
        uid,
        ppid: ppid as u32,
        comm: cmd_buf,
        ret: 0,
        is_exit: false,
    };

    unsafe {
        bpf_perf_event_output(
            ctx.as_ptr(),
            &EVENTS as *const _ as *mut _,
            BPF_F_CURRENT_CPU,
            &event as *const Event as *const u8 as *mut _,
            core::mem::size_of::<Event>() as u64,
        )
    };
    // info!(&ctx, "Event: pid: {}, uid: {}, ppid: {}", event.pid, event.uid, event.ppid);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
