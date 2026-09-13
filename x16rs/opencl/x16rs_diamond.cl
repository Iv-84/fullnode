#include "util.cl"
#include "x16rs.cl"
#include "sha3_256.cl"

// Diamond name calculation constants
#define DMD_M 16
#define H32S 32
#define DIAMOND_HASH_BASE_CHAR_NUM 17
__constant uchar DIAMOND_HASH_BASE_CHARS[DIAMOND_HASH_BASE_CHAR_NUM] = "0WTYUIAHXVMEKBSZN";

// Mirror of x16rs::check_diamond_difficulty step 1 (see x16rs/src/diamond.rs).
__constant uchar DIAMOND_MODIFFBITS[H32S] = {
    128, 132, 136, 140, 144, 148, 152, 156,
    160, 164, 168, 172, 176, 180, 184, 188, 192, 196, 200, 204, 208, 212, 216, 220, 224, 228,
    232, 236, 240, 244, 248, 252
};

inline int diff_big_hash(const hash_32 *src, const hash_32 *tar)
{
    #pragma unroll 32
    for (int i = 0; i < 32; i++) {
        if (src->h1[i] > tar->h1[i]) {
            return 1;
        } else if (src->h1[i] < tar->h1[i]) {
            return 0;
        }
    }
    return 0;
}

/*
 * Difficulty step 1 depends on the SHA3 digest alone and is a necessary
 * condition, so a nonce that fails here can never produce a diamond no matter
 * what X16RS would return. Gating on it before the X16RS chain is what keeps
 * the expensive half (x16rs_repeat rounds) off ~9 nonces out of every 10.
 *
 * gate_modiff_len is `number / 42000` and gate_max_byte is `255 - number / 65536`,
 * both computed host-side so the wrap-around semantics stay identical to Rust.
 */
inline bool diamond_sha3_gate(const uchar *sha3hx,
                              const uint gate_modiff_len,
                              const uchar gate_max_byte)
{
    for (uint i = 0u; i < (uint)H32S; i++) {
        if (i < gate_modiff_len && sha3hx[i] >= DIAMOND_MODIFFBITS[i]) {
            return false;
        }
        if (sha3hx[i] > gate_max_byte) {
            return false;
        }
    }
    return true;
}

inline void diamond_hash(const uchar *bshash, uchar *reshx)
{
    uint mgcidx = 13u;
    for (uint i = 0u; i < (uint)DMD_M; i++) {
        uint a = (uint)bshash[i * 2u];
        uint b = (uint)bshash[i * 2u + 1u];
        uint num = mgcidx * a * b;
        mgcidx = num % (uint)DIAMOND_HASH_BASE_CHAR_NUM;
        reshx[i] = DIAMOND_HASH_BASE_CHARS[mgcidx];
        if (mgcidx == 0u) mgcidx = 13u;
    }
}

inline bool diamond_more_power(const uchar *dst,
                                 const uchar *src)
{
     const uchar o = (uchar)'0';
    for (uint i = 0u; i < 16u; i++) {
        uchar l = dst[i];
        uchar r = src[i];
        if (l == o && r != o) return 1;
        if (l != o && r == o) return 0;
        if (l != o && r != o) return 0;
    }
    return 0;
}

inline bool diamond_hash_result_valid(const uchar *name)
{
    const uchar o = (uchar)'0';
    for (uint i = 0u; i < 10u; i++) {
        if (name[i] != o) return 0;
    }
    for (uint i = 10u; i < 16u; i++) {
        if (name[i] == o) return 0;
    }
    return 1;
}

inline bool diamond_candidate_more_power(const uchar *dst,
                                         const uchar *src)
{
    bool dst_valid = diamond_hash_result_valid(dst);
    bool src_valid = diamond_hash_result_valid(src);
    if (dst_valid != src_valid) return dst_valid;
    return diamond_more_power(dst, src);
}

__attribute__((work_group_size_hint(256, 1, 1)))
__kernel void x16rs_diamond(
    __constant const block_diamond_t* input_stuff,
    const ulong nonce_start,
    const unsigned int x16rs_repeat,
    const unsigned int unit_size,
    const unsigned int probe_span,
    const unsigned int gate_modiff_len,
    const unsigned int gate_max_byte,
    __global hash_32* global_hashes,
    __global unsigned int* global_order,
    __global ulong* global_slot_nonces,
    __global ulong* global_probe_counts,
    __global hash_32* best_hashes,
    __global ulong* best_nonces,
    __global ulong* candidate_nonces,
    volatile __global unsigned int* candidate_count,
    const unsigned int max_candidates
) {
    const unsigned int local_id = get_local_id(0);
    const unsigned int local_size = get_local_size(0);
    const unsigned int group_id = get_group_id(0);
    const unsigned int index = local_id * unit_size;
    hash_32* local_hashes = global_hashes + (group_id * local_size * unit_size);
    __global ulong* slot_nonces = global_slot_nonces + ((size_t)group_id * (size_t)local_size * (size_t)unit_size);
    __local ulong local_nonces[256];
    __global unsigned int* local_order = global_order + (group_id * local_size * unit_size);
    __local unsigned int ALIGN histogram[16];
    __local unsigned int ALIGN starting_index[16];
    __local unsigned int ALIGN offset[16];
    __local unsigned int group_probed;

    // Setup x16 local shared vars
    X16RS_INIT_SHARED_TABLES(local_id, local_size);

    block_diamond_t base_stuff = input_stuff[0];

    if (local_id == 0) {
        group_probed = 0u;
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    /*
     * Probe this work item's private nonce span with SHA3 only, and keep the
     * survivors of the step-1 gate until the X16RS slots are full. Every slot
     * handed to the X16RS loop below is therefore a nonce that can still win,
     * instead of ~89% dead weight.
     */
    const ulong probe_base = nonce_start + ((ulong)get_global_id(0) * (ulong)probe_span);
    const uchar gate_max = (uchar)gate_max_byte;
    unsigned int filled = 0u;
    unsigned int probed = 0u;
    hash_32 candidate;
    while (probed < probe_span && filled < unit_size) {
        volatile const ulong nonce = probe_base + probed;
        // Insert Nonce
        write_nonce_u64_to_bytes(32, base_stuff.h1, nonce);
        // Hash Block
        sha3_256_hash_diamond(base_stuff.h8, candidate.h8);
        probed++;
        if (diamond_sha3_gate(candidate.h1, gate_modiff_len, gate_max)) {
            local_hashes[index + filled] = candidate;
            slot_nonces[index + filled] = nonce;
            filled++;
        }
    }
    /*
     * The shared X16RS loop always walks a full batch, so pad any unused slots.
     * Duplicating the last survivor keeps every slot a consistent hash/nonce
     * pair. Finding no survivor at all in a whole span is vanishingly unlikely;
     * if it happens we keep the last probe and the host rejects it on
     * re-validation, costing this batch and nothing else.
     */
    if (filled == 0u) {
        local_hashes[index] = candidate;
        slot_nonces[index] = probe_base + (probed > 0u ? probed - 1u : 0u);
    }
    const unsigned int pad_src = index + (filled == 0u ? 0u : filled - 1u);
    for (unsigned int i = (filled == 0u ? 1u : filled); i < unit_size; i++) {
        local_hashes[index + i] = local_hashes[pad_src];
        slot_nonces[index + i] = slot_nonces[pad_src];
    }
    atomic_add(&group_probed, probed);
    /*
     * local_hashes lives in global memory and the X16RS loop below has work
     * items touching each other's slots, so this hand-off needs a global fence
     * and not just a local one.
     */
    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);

    if (local_id == 0) {
        // real work done, for honest hashrate accounting host-side
        global_probe_counts[group_id] = (ulong)group_probed;
    }

    X16RS_RUN_REPEAT_LOOP(
        local_id, local_size, unit_size, x16rs_repeat,
        local_hashes, index, local_order,
        histogram, starting_index, offset,
        H_blake,
        T0, T1, T2, T3,
        AES0, AES1, AES2, AES3,
        LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7,
        mixtab0, mixtab1, mixtab2, mixtab3
    );

    // the loop above left this work item's slots written by other work items
    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);

    unsigned int best_hash = index;
    diamond_t best_name;
    diamond_hash(local_hashes[index].h1, best_name.h1);
    for (unsigned int i = 0; i < unit_size; i++) {
        // Get diamond name
        unsigned int now_hash = index + i;
        diamond_t now_name;
        diamond_hash(local_hashes[now_hash].h1, now_name.h1);
        /*
         * The SHA3 gate broke the old slot -> nonce arithmetic, so the nonce
         * has to come from slot_nonces. Only the first `filled` slots hold
         * distinct survivors: anything past that is padding duplicated from the
         * last one, and reporting it would hand the host the same diamond twice.
         */
        if (i < filled && diamond_hash_result_valid(now_name.h1) == 1) {
            unsigned int slot = atomic_inc(candidate_count);
            if (slot < max_candidates) {
                candidate_nonces[slot] = slot_nonces[now_hash];
            }
        }
        if (i > 0 && diamond_candidate_more_power(now_name.h1, best_name.h1) == 1) {
            best_hash = now_hash;
            best_name = now_name;
        }
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    local_nonces[local_id] = slot_nonces[best_hash];
    local_hashes[index] = local_hashes[best_hash];

    barrier(CLK_LOCAL_MEM_FENCE);

    // Now perform the reduction across threads
    for (unsigned int smax = local_size >> 1; smax > 0; smax >>= 1) {
        if (local_id < smax) {
            unsigned int idx_current = index;
            unsigned int idx_pair = (local_id + smax) * unit_size;
            diamond_t current_name;
            diamond_t pair_name;
            diamond_hash(local_hashes[idx_current].h1, current_name.h1);
            diamond_hash(local_hashes[idx_pair].h1, pair_name.h1);
            if (diamond_candidate_more_power(pair_name.h1, current_name.h1) == 1) {
                local_hashes[idx_current] = local_hashes[idx_pair];
                local_nonces[local_id] = local_nonces[local_id + smax];
            }
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }

    if(local_id == 0) {
        best_nonces[group_id] = local_nonces[0];
    }
    if(local_id < 32) {
        best_hashes[group_id].h1[local_id] = local_hashes[0].h1[local_id];
    }
}
