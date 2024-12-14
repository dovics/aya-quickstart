#![no_std]
#![no_main]

mod vmlinux;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_ringbuf_reserve, bpf_ringbuf_submit},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use quickstart_common::exit_event::Event;
use vmlinux::task_struct;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024, 0);

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let size = core::mem::size_of::<Event>();
    let event_ptr =
        unsafe { bpf_ringbuf_reserve(&EVENTS as *const RingBuf as *mut _, size as u64, 0) };
    if event_ptr.is_null() {
        return 0;
    }

    let event = unsafe { &mut *(event_ptr as *mut Event) };
    let task_ptr = unsafe { bpf_get_current_task_btf() as *const task_struct };    
    let task = unsafe { core::ptr::read(task_ptr) };
    event.pid = pid;
    event.duration = unsafe { bpf_ktime_get_ns() } - task.start_time;
    event.ppid = unsafe { (*task.real_parent).pid as u32 };
    event.exit_code = task.exit_code;
    event.comm  = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe { bpf_ringbuf_submit(event_ptr, 0) };
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
