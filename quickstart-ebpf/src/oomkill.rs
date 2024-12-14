#![no_std]
#![no_main]

mod vmlinux;

use core::mem::offset_of;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
};

use quickstart_common::oom_event::Event;
use vmlinux::{oom_control, task_struct};

const TASK_COMM_OFFSET: usize = offset_of!(task_struct, comm);
const TASK_PID_OFFSET: usize = offset_of!(task_struct, pid);

const OC_TASK_OFFSET: usize = offset_of!(oom_control, chosen);
const OC_TOTALPAGES_OFFSET: usize = offset_of!(oom_control, totalpages);

#[map]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[kprobe]
pub fn kprobe_oomkill(ctx: ProbeContext) -> u32 {
    match try_oomkill(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_oomkill(ctx: ProbeContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid() >> 32;

    let oc_ptr: *const oom_control = ctx.arg(0).ok_or(1)?;
    let oc_ptr = oc_ptr as usize;
    let oc_totalpages =
        unsafe { bpf_probe_read_kernel((oc_ptr as usize + OC_TOTALPAGES_OFFSET) as *const u64) }?;
    let task_ptr = unsafe { bpf_probe_read_kernel((oc_ptr + OC_TASK_OFFSET) as *const usize) }?;

    let task_comm =
        unsafe { bpf_probe_read_kernel((task_ptr + TASK_COMM_OFFSET) as *const [u8; 16]) }?;
    let task_pid = unsafe { bpf_probe_read_kernel((task_ptr + TASK_PID_OFFSET) as *const u32) }?;
    let current_comm = bpf_get_current_comm()?;

    let event = Event {
        fpid: pid as u32,
        tpid: task_pid,
        pages: oc_totalpages,
        fcomm: current_comm,
        tcomm: task_comm,
    };

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
