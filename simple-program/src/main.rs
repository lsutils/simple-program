use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Context as _;
use aya::{
    maps::{AsyncPerfEventArray, HashMap},
    programs::{tc, CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, KProbe, Lsm, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    util::online_cpus,
    Btf,
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use bytes::BytesMut;
use log::info;
use simple_program_common::PacketLog;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/simple-program")))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    {
        let program: &mut Xdp = ebpf.program_mut("xdp_firewall").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&opt.iface, XdpFlags::SKB_MODE)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("XDPBLOCKLIST").unwrap())?;
        let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;
        blocklist.insert(block_addr, 0, 0)?;
    }
    {
        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        let _ = tc::qdisc_add_clsact(&opt.iface);
        let program: &mut SchedClassifier = ebpf.program_mut("tc_egress").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.iface, TcAttachType::Egress)?;

        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("TC_BLOCK_LIST").unwrap())?;
        let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;

        blocklist.insert(block_addr, 0, 0)?;
    }
    {
        let program: &mut KProbe = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
        program.load()?;
        program.attach("tcp_connect", 0)?;
    }
    {
        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = ebpf.program_mut("task_alloc").unwrap().try_into()?;
        program.load("task_alloc", &btf)?;
        program.attach()?;

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }
    {
        let program: &mut CgroupSkb = ebpf.program_mut("cgroup_skb_egress").unwrap().try_into()?;
        let cgroup = std::fs::File::open(opt.cgroup_path)?;
        program.load()?;
        program.attach(cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)?;

        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("CGROUPBLOCKLIST").unwrap())?;
        let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;
        blocklist.insert(block_addr, 0, 0)?;

        let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

        for cpu_id in online_cpus().map_err(|(_, error)| error)? {
            let mut buf = perf_array.open(cpu_id, None)?;

            task::spawn(async move {
                let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let ptr = buf.as_ptr() as *const PacketLog;
                        let data = unsafe { ptr.read_unaligned() };
                        let src_addr = Ipv4Addr::from(data.ipv4_address);
                        info!("LOG: DST {}, ACTION {}", src_addr, data.action);
                    }
                }
            });
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
