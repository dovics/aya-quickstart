use aya::{include_bytes_aligned, maps::PerfEventArray, programs::KProbe, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn};
use quickstart_common::oom_event::Event;
use chrono::Local;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/oomkill-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/oomkill-ebpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut KProbe =
        bpf.program_mut("kprobe_oomkill").unwrap().try_into()?;
    program.load()?;
    program.attach("oom_kill_process", 0)?;

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
                let tcomm = String::from_utf8(event.tcomm.to_vec()).unwrap();
                let fcomm = String::from_utf8(event.fcomm.to_vec()).unwrap();
                let now = Local::now().format("%H:%M:%S");

                info!("{} Triggered by PID {} ({}), OOM kill of PID {} ({}), {} pages, loadavg", now, event.fpid, fcomm, event.tpid,tcomm,  event.pages);
            }
        });
    }
}
