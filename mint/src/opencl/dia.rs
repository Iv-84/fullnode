use ocl::{Buffer, EventList, Kernel};

use field::{Address, DiamondName, DiamondNumber, Fixed8, Hash};

use crate::action::diamond::HacdMint;
use crate::diamond_mining::{
    DiamondMiningResult, HASH_WIDTH, check_diamond_success, diamond_candidate_more_power,
};

use super::common::{OpenCLResources, enqueue_kernel_checked};

pub fn do_diamond_group_mining_opencl(
    opencl: &OpenCLResources,
    number: u32,
    prevblockhash: &Hash,
    reward_address: &Address,
    custom_message: &Hash,
    nonce_start: u64,
    nonce_space: u64,
    num_work_groups: u32,
    local_work_size: u32,
    unit_size: u32,
) -> DiamondMiningResult {
    let empty = [0u8; 0];
    let custom_nonce = if number
        > hacash_params::MAINNET_PARAMS
            .mint_rules
            .diamond
            .custom_message_after
    {
        custom_message.as_ref()
    } else {
        &empty
    };
    let mut best = DiamondMiningResult {
        number,
        nonce_start,
        nonce_space,
        nonce: 0,
        diamond_string: [b'W'; 16],
        successes: Vec::new(),
        elapsed_secs: 0.0,
    };

    let global_work_size = num_work_groups.saturating_mul(local_work_size);
    let repeat = x16rs::mine_diamond_hash_repeat(number) as u32;
    let stuff = [
        prevblockhash.as_ref(),
        [0u8; 8].as_slice(),
        reward_address.as_ref(),
        custom_nonce,
    ]
    .concat();

    let buffer_block_intro = Buffer::<u8>::builder()
        .queue(opencl.queue.clone())
        .flags(ocl::core::MEM_READ_ONLY)
        .len(stuff.len())
        .copy_host_slice(&stuff)
        .build()
        .expect("unable to create diamond OpenCL input buffer");

    opencl
        .buffer_diamond_candidate_count
        .write(&[0u32][..])
        .enq()
        .expect("can't reset diamond candidate count");

    let kernel = Kernel::builder()
        .program(&opencl.program)
        .name("x16rs_diamond")
        .queue(opencl.queue.clone())
        .global_work_size(global_work_size)
        .local_work_size(local_work_size)
        .arg(&buffer_block_intro)
        .arg(nonce_start)
        .arg(repeat)
        .arg(unit_size)
        .arg(&opencl.buffer_global_hashes)
        .arg(&opencl.buffer_global_order)
        .arg(&opencl.buffer_best_hashes)
        .arg(&opencl.buffer_best_nonces_diamond)
        .arg(&opencl.buffer_diamond_candidate_nonces)
        .arg(&opencl.buffer_diamond_candidate_count)
        .arg(opencl.diamond_candidate_capacity as u32)
        .build()
        .expect("unable to build diamond OpenCL kernel");

    let mut kernel_event = EventList::new();
    enqueue_kernel_checked(
        &kernel,
        &mut kernel_event,
        "unable to queue diamond OpenCL kernel",
    );

    let mut hashes = vec![0u8; opencl.buffer_best_hashes.len()];
    opencl
        .buffer_best_hashes
        .read(&mut hashes)
        .ewait(&kernel_event)
        .enq()
        .expect("can't read diamond best hashes");

    let mut nonces = vec![0u64; opencl.buffer_best_nonces_diamond.len()];
    opencl
        .buffer_best_nonces_diamond
        .read(&mut nonces)
        .ewait(&kernel_event)
        .enq()
        .expect("can't read diamond best nonces");

    let mut candidate_count = [0u32];
    opencl
        .buffer_diamond_candidate_count
        .read(&mut candidate_count[..])
        .ewait(&kernel_event)
        .enq()
        .expect("can't read diamond candidate count");
    let candidate_count = (candidate_count[0] as usize).min(opencl.diamond_candidate_capacity);
    if candidate_count > 0 {
        let mut candidate_nonces = vec![0u64; candidate_count];
        opencl
            .buffer_diamond_candidate_nonces
            .read(&mut candidate_nonces)
            .ewait(&kernel_event)
            .enq()
            .expect("can't read diamond candidate nonces");
        for nonce in candidate_nonces {
            let nonce_bytes = nonce.to_be_bytes();
            let (first_hash, result_hash, diamond_string) = x16rs::mine_diamond(
                number,
                &prevblockhash.into_array(),
                &nonce_bytes,
                reward_address.as_array(),
                custom_nonce,
            );
            if let Some(diamond_name) =
                check_diamond_success(number, first_hash, result_hash, diamond_string)
            {
                let mut act =
                    HacdMint::with(DiamondName::from(diamond_name), DiamondNumber::from(number));
                act.d.prev_hash = *prevblockhash;
                act.d.nonce = Fixed8::from(nonce_bytes);
                act.d.address = *reward_address;
                act.d.custom_message = *custom_message;
                best.successes.push(act);
            }
            if diamond_candidate_more_power(&diamond_string, &best.diamond_string) {
                best.diamond_string = diamond_string;
                best.nonce = nonce;
            }
        }
    }

    for i in 0..num_work_groups as usize {
        let mut hash = [0u8; HASH_WIDTH];
        hash.copy_from_slice(&hashes[i * HASH_WIDTH..(i + 1) * HASH_WIDTH]);
        let diamond_string = x16rs::diamond_hash(&hash);
        if diamond_candidate_more_power(&diamond_string, &best.diamond_string) {
            best.diamond_string = diamond_string;
            best.nonce = nonces[i];
        }
    }

    best
}
