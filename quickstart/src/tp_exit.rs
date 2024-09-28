use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, debug, warn};
use std::convert::TryFrom;
use std::ops::Deref;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use quickstart_common::exit_event::Event;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tp-exit-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tp-exit-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let enter_program: &mut TracePoint =
        bpf.program_mut("sched_process_exit").unwrap().try_into()?;
    enter_program.load()?;
    enter_program
        .attach("sched", "sched_process_exit")
        .context("failed to attach the TracePoint program")?;

    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let mut poll = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;

    loop {
        let mut guard = poll.ready_mut(Interest::READABLE).await?;
        
        if guard.ready().is_readable() {
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let event = unsafe { &*(item.deref() as *const [u8] as *const Event) };
                let comm = String::from_utf8(event.comm.to_vec()).unwrap();
                info!("Received: pid: {}, ppid: {}, exit_code: {}, duration: {}, comm: {}", 
                    event.pid, event.ppid, event.exit_code, event.duration, comm);
            }
            guard.clear_ready();
        }
    }
}
