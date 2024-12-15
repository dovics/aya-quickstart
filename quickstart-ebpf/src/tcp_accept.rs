#![no_std]
#![no_main]
mod vmlinux;

use core::mem::offset_of;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::kretprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use network_types::ip::IpProto;
use vmlinux::{sock, sock_common};

#[kretprobe]
pub fn kretprobe_inet_csk_accept(ctx: ProbeContext) -> u32 {
    match try_inet_csk_accept(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_inet_csk_accept(ctx: ProbeContext) -> Result<u32, i64> {
    info!(&ctx, "kretprobe_inet_csk_accept");
    let sk_ptr: *const sock = ctx.ret().ok_or(0)?;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let skc = unsafe { bpf_probe_read_kernel(sk_ptr as *const sock_common) }?;
    
    let field_offset = offset_of!(sock, sk_protocol);
    let protocol = unsafe { bpf_probe_read_kernel((sk_ptr as usize + field_offset) as *const u16) }?;

    if protocol != IpProto::Tcp as u16 {
        return Ok(0);
    }

    let family = skc.skc_family;
    let lport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_num };
    let dport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_dport };

    info!(
        &ctx,
        "accepted: pid: {}, family: {}, lport: {}, dport: {}", pid, family, lport, dport
    );

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
