use crate::action::diamond::HacdMint;

pub const HASH_WIDTH: usize = 32;

#[derive(Clone)]
pub struct DiamondMiningResult {
    pub number: u32,
    pub nonce_start: u64,
    pub nonce_space: u64,
    pub nonce: u64,
    pub diamond_string: [u8; 16],
    pub successes: Vec<HacdMint>,
    pub elapsed_secs: f64,
}

pub fn check_diamond_success(
    number: u32,
    first_hash: [u8; HASH_WIDTH],
    result_hash: [u8; HASH_WIDTH],
    diamond_string: [u8; 16],
) -> Option<[u8; 6]> {
    let diamond_name = x16rs::check_diamond_hash_result(diamond_string)?;
    x16rs::check_diamond_difficulty(number, &first_hash, &result_hash).then_some(diamond_name)
}

pub fn diamond_more_power(dst: &[u8], src: &[u8]) -> bool {
    for i in 0..16 {
        let (l, r) = (dst[i], src[i]);
        if l == b'0' && r != b'0' {
            return true;
        }
        if l != b'0' && r == b'0' {
            return false;
        }
        if l != b'0' && r != b'0' {
            return false;
        }
    }
    false
}

pub fn diamond_hash_result_valid(name: &[u8]) -> bool {
    x16rs::check_diamond_hash_result(name).is_some()
}

pub fn diamond_candidate_more_power(dst: &[u8], src: &[u8]) -> bool {
    let dst_valid = diamond_hash_result_valid(dst);
    let src_valid = diamond_hash_result_valid(src);
    if dst_valid != src_valid {
        return dst_valid;
    }
    diamond_more_power(dst, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diamond_name_validity_matches_consensus() {
        assert!(diamond_hash_result_valid(b"0000000000WTYUIA"));
        assert!(!diamond_hash_result_valid(b"000000000WTYUIAH"));
        assert!(!diamond_hash_result_valid(b"00000000000TYUIA"));
        assert!(!diamond_hash_result_valid(b"0000000000WTYUI0"));
        assert!(!diamond_hash_result_valid(b"0000000000WTYUI"));
    }

    #[test]
    fn overshooting_name_does_not_mask_valid_diamond() {
        let valid = b"0000000000WTYUIA";
        let overshoot = b"00000000000TYUIA";
        assert!(diamond_more_power(overshoot, valid));
        assert!(!diamond_candidate_more_power(overshoot, valid));
        assert!(diamond_candidate_more_power(valid, overshoot));
    }

    #[test]
    fn invalid_candidates_still_rank_by_leading_zeros() {
        let closer = b"00000WTYUIAHXVMK";
        let further = b"WTYUIAHXVMEKBSZN";
        assert!(diamond_candidate_more_power(closer, further));
        assert!(!diamond_candidate_more_power(further, closer));
    }

    #[test]
    fn initial_sentinel_loses_to_candidates() {
        let sentinel = [b'W'; 16];
        assert!(diamond_candidate_more_power(
            b"0000000000WTYUIA",
            &sentinel
        ));
        assert!(diamond_candidate_more_power(
            b"00000WTYUIAHXVMK",
            &sentinel
        ));
    }
}
