use anyhow::Context;
use aya::maps::PerfEventArray;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use aya::util::online_cpus;
use bytes::BytesMut;
use quickstart_common::execve_event::Event;

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
        "../../target/bpfel-unknown-none/debug/tp-execve-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tp-execve-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    program.load()?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach the TracePoint program")?;
    let mut events =
        PerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus()? {
        perf_buffers.push(events.open(cpu_id, None)?);
    }

    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();

    loop {
        perf_buffers.iter_mut().for_each(|buf| {
            let events = buf.read_events(&mut buffers).unwrap();
            for i in 0..events.read {
                let event = unsafe { &*(buffers[i].as_ptr() as *const Event as *const Event) };
                let comm = String::from_utf8(event.comm.to_vec()).unwrap();
                info!("pid: {}, ppid: {}, uid: {}, comm: {}", event.pid, event.ppid, event.uid, comm);
            }
        });
    }
}
