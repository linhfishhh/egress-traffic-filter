#![no_std]
#![no_main]

use core::mem::{self, offset_of};

use aya_ebpf::{
  bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
  macros::classifier,
  programs::TcContext,
  EbpfContext,
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;
use vmlinux::{ethhdr, iphdr};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[classifier]
pub fn egress_traffic_filter(ctx: TcContext) -> i32 {
  match try_egress_traffic_filter(ctx) {
    Ok(ret) => ret,
    Err(_) => TC_ACT_SHOT,
  }
}

fn try_egress_traffic_filter(ctx: TcContext) -> Result<i32, i64> {
  let h_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto)).map_err(|_| TC_ACT_PIPE)?);
  // only process ipv4 and ipv6 packet
  let ip_version: u32 = match h_proto {
    ETH_P_IP => 4,
    ETH_P_IPV6 => 6,
    _ => return Ok(TC_ACT_PIPE),
  };
  let destination: u128 = match ip_version {
    4 => u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, __bindgen_anon_1.__bindgen_anon_1.daddr))?) as u128,
    6 => u128::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, __bindgen_anon_1.__bindgen_anon_1.daddr))?),
    _ => 0,
  };

  let uid = ctx.get_socket_uid();

  let mut ip_address: [u32; 4] = [0; 4];

  let mut counter = 0;
  for chunk in (destination as u128).to_le_bytes().chunks(4) {
    ip_address[counter] = u32::from_le_bytes(chunk.try_into().expect("Internal Error: Size of Chunks is not 4 bytes"));
    counter += 1;
  }

  match ip_version {
    4 => {
      let ip_address = destination as u32;
      info!(&ctx, "VERSION {}, DEST {:i}, UID {}", ip_version, ip_address, uid)
    },
    6 => {
      let ip_address = (destination as u128).to_le_bytes();
      info!(&ctx, "VERSION {}, DEST {:i} , UID {}", ip_version, ip_address, uid)
    },
    _ => info!(&ctx, "Unkown IP version {}, UID {}", ip_version, uid),
  }
  Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  loop {}
}
