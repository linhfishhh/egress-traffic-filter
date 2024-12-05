use std::net::Ipv4Addr;

use aya::{
  maps::HashMap,
  programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
  #[clap(short, long, default_value = "eth0")]
  iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let opt = Opt::parse();

  env_logger::init();

  let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
  let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
  if ret != 0 {
    debug!("remove limit on locked memory failed, ret is: {}", ret);
  }

  let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/egress-traffic-filter")))?;
  if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
    warn!("failed to initialize eBPF logger: {}", e);
  }
  let Opt { iface } = opt;
  let _ = tc::qdisc_add_clsact(&iface);
  let program: &mut SchedClassifier = ebpf.program_mut("egress_traffic_filter").unwrap().try_into()?;
  program.load()?;
  program.attach(&iface, TcAttachType::Egress)?;

  let mut blocklist: HashMap<_, u128, u128> = HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

  let block_addr: u32 = Ipv4Addr::new(169, 254, 169, 254).into();

  blocklist.insert(block_addr as u128, 0, 0);

  let ctrl_c = signal::ctrl_c();
  println!("Waiting for Ctrl-C...");
  ctrl_c.await?;
  println!("Exiting...");

  Ok(())
}
