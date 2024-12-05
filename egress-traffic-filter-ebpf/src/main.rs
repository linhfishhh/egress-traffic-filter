#![no_std]
#![no_main]

use core::net::Ipv6Addr;

use aya_ebpf::{
  bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
  macros::{classifier, map},
  maps::HashMap,
  programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
  eth::{EthHdr, EtherType},
  ip::Ipv4Hdr,
};

#[map]
static BLOCKLIST: HashMap<u128, u128> = HashMap::with_max_entries(1024, 0);
#[classifier]
pub fn egress_traffic_filter(ctx: TcContext) -> i32 {
  match try_egress_traffic_filter(ctx) {
    Ok(ret) => ret,
    Err(_) => TC_ACT_SHOT,
  }
}

fn try_egress_traffic_filter(ctx: TcContext) -> Result<i32, ()> {
  let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

  //only process ip v4 or ip v6
  let ip_version = match ethhdr.ether_type {
    EtherType::Ipv4 => 4,
    EtherType::Ipv6 => 6,
    _ => return Ok(TC_ACT_PIPE),
  };

  let dest_addr: u128 = match ip_version {
    4 => {
      let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
      let destination = u32::from_be(ipv4hdr.dst_addr);
      destination as u128
    },
    6 => {
      let ipv6hdr: Ipv6Addr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
      let destination = u128::from_be_bytes(ipv6hdr.octets());
      destination
    },
    _ => return Ok(TC_ACT_PIPE),
  };

  let action = if block_ip(dest_addr) { TC_ACT_SHOT } else { TC_ACT_PIPE };

  match ip_version {
    4 => {
      let ip_address = dest_addr as u32;
      info!(&ctx, "VERSION {}, DEST {:i}, action: {}", ip_version, ip_address, action)
    },
    6 => {
      let ip_address = (dest_addr as u128).to_le_bytes();
      info!(&ctx, "VERSION {}, DEST {:i}, action: {}", ip_version, ip_address, action)
    },
    _ => info!(&ctx, "Unkown IP version {}, action: {}", ip_version, action),
  };

  Ok(action)
}

fn block_ip(address: u128) -> bool {
  unsafe { BLOCKLIST.get(&address).is_some() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  loop {}
}
