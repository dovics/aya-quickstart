#![no_std]
#![no_main]
mod vmlinux;

use core::{mem::offset_of, str::{from_utf8, from_utf8_unchecked}};

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
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

macro_rules! filed_of {
    ($ptr:ident ,$ty:ty, $field:ident) => {{
        let filed_offset = offset_of!($ty, $field);
        unsafe { bpf_probe_read_kernel(($ptr as usize + filed_offset) as *const _) }?
    }};
}

fn try_inet_csk_accept(ctx: ProbeContext) -> Result<u32, i64> {
    let sk_ptr: *const sock = ctx.ret().ok_or(0)?;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let skc: sock_common = filed_of!(sk_ptr, sock, __sk_common);
    let protocol: u16 = filed_of!(sk_ptr, sock, sk_protocol);

    if protocol != IpProto::Tcp as u16 {
        return Ok(0);
    }

    let family = skc.skc_family;
    let lport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_num };
    let dport = unsafe { skc.__bindgen_anon_3.__bindgen_anon_1.skc_dport };

    let saddr = unsafe { skc.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr };
    let daddr = unsafe { skc.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };

    let comm = bpf_get_current_comm()?;
    
    let comm_str = unsafe { from_utf8_unchecked(&comm) };
    info!(
        &ctx,
        "accepted: pid: {}, family: {}, lport: {}, dport: {}, saddr: {}, daddr: {}, comm: {}",
        pid,
        family,
        lport,
        dport,
        saddr,
        daddr,
        comm_str,
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
