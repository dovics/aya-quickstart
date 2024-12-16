use aya::maps::PerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn};

use quickstart_common::connect_event::IPv4Data;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcpconnect-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcpconnect-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let entry_program: &mut KProbe = bpf
        .program_mut("kprobe_tcp_connect_entry")
        .unwrap()
        .try_into()?;
    entry_program.load()?;
    entry_program.attach("tcp_v4_connect", 0)?;

    let return_program: &mut KProbe = bpf
        .program_mut("kretprobe_tcp_connect_return")
        .unwrap()
        .try_into()?;
    return_program.load()?;
    return_program.attach("tcp_v4_connect", 0)?;

    let mut events = PerfEventArray::try_from(bpf.map_mut("IPV4_EVENT").unwrap())?;

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
                let event =
                    unsafe { &*(buffers[i].as_ptr() as *const IPv4Data as *const IPv4Data) };
                let comm = String::from_utf8(event.comm.to_vec()).unwrap();
                info!(
                    "ts:{}, pid:{}, uid:{}, saddr:{}, daddr:{}, lport:{}, dport:{}, ret:{}, comm:{}", event.ts_us, event.pid, event.uid, event.saddr, event.daddr, event.lport, event.dport, event.ret, comm
                );
            }
        });
    }
}
