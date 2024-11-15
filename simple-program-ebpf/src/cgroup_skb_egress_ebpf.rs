use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::{HashMap, PerfEventArray},
    programs::SkBuffContext,
};
use memoffset::offset_of;
use simple_program_common::PacketLog;

use crate::task_struct::{iphdr, iphdr__bindgen_ty_1__bindgen_ty_1};

// 需要cgroup v2

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[map]
static CGROUPBLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    { try_cgroup_skb_egress(ctx) }.unwrap_or_else(|_| 0)
}

fn block_ip(address: u32) -> bool {
    unsafe { CGROUPBLOCKLIST.get(&address).is_some() }
}

const ETH_P_IP: u32 = 8;

fn try_cgroup_skb_egress(ctx: SkBuffContext) -> Result<i32, i64> {
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    if protocol != ETH_P_IP {
        return Ok(1);
    }

    let offset_of_bindgen_anon_1 = offset_of!(iphdr, __bindgen_anon_1);
    let offset_of_daddr_in_bindgen_anon_1 = offset_of!(iphdr__bindgen_ty_1__bindgen_ty_1, daddr);
    let total_offset_of_daddr = offset_of_bindgen_anon_1 + offset_of_daddr_in_bindgen_anon_1;

    let destination = u32::from_be(ctx.load(total_offset_of_daddr)?);

    let action = if block_ip(destination) { 0 } else { 1 };

    let log_entry = PacketLog {
        ipv4_address: destination,
        action,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action as i32)
}
