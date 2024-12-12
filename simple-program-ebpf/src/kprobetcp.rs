use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

use crate::task_struct::{sock, sock_common};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    try_kprobetcp(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    // bpf_probe_read_user
    // bpf_probe_read_kernel
    let sk_common = unsafe { bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)? };
    match sk_common.skc_family {
        AF_INET => {
            let src_addr = u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 = u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            info!(&ctx, "AF_INET src address: {:i}, dest address: {:i}", src_addr, dest_addr,);
            Ok(0)
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(&ctx, "AF_INET6 src addr: {:i}, dest addr: {:i}", unsafe { src_addr.in6_u.u6_addr8 }, unsafe {
                dest_addr.in6_u.u6_addr8
            });
            Ok(0)
        }
        _ => Ok(0),
    }
}
