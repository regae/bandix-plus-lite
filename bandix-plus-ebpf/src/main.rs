#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;

#[classifier]
pub fn bandix_plus(ctx: TcContext) -> i32 {
    match try_bandix_plus(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bandix_plus(ctx: TcContext) -> Result<i32, i32> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    info!(&ctx, "ifindex {}", ifindex);
    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
