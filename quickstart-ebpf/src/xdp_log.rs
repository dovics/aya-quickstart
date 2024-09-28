#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EtherType, EthHdr},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
    tcp::TcpHdr,
};
use core::mem;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, mem::size_of::<EthHdr>())?;
    let source_addr = u32::from_be(unsafe {(*ip_hdr).src_addr});

    let source_port = match unsafe { (*ip_hdr).proto } {
        IpProto::Udp => {
            let udp_hdr = ptr_at::<UdpHdr>(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>())?;
            u16::from_be(unsafe { (*udp_hdr).source })
        }
        IpProto::Tcp => {
            let tcp_hdr = ptr_at::<TcpHdr>(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>())?;
            u16::from_be(unsafe { (*tcp_hdr).source })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(&ctx, "received a packet from {} port {}", source_addr, source_port);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
