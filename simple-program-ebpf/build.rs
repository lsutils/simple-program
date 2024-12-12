use std::{fs::File, io::Write, path::PathBuf};

use aya_tool::generate::InputFile;
use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() -> Result<(), anyhow::Error> {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

    let base_path = "./src";
    let dir = PathBuf::from(base_path);
    let names: Vec<&str> = vec!["iphdr"];
    let bindings = aya_tool::generate(InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")), &names, &[])?;

    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{bindings}")?;

    let names: Vec<&str> = vec!["task_struct"];
    let bindings = aya_tool::generate(InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")), &names, &[])?;
    let mut out = File::create(dir.join("task_struct.rs"))?;
    write!(out, "{bindings}")?;

    Ok(())
}
