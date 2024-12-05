use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
  let dir = PathBuf::from("egress-traffic-filter-ebpf/src");
  let names: Vec<&str> = vec!["ethhdr", "iphdr"];
  let bindings = aya_tool::generate(InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")), &names, &[])?;
  let mut out = File::create(dir.join("vmlinux.rs"))?;
  write!(out, "{}", bindings)?;
  Ok(())
}
