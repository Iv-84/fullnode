use x16rs::*;

// deterministic xorshift64*, so the staged-check tests are reproducible
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn hash(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b
    }
}

/// Splitting check_diamond_difficulty into a SHA3 stage and an X16RS stage must
/// not move consensus by a single nonce: the conjunction has to agree with the
/// original predicate on every input.
#[test]
fn t_diamond_difficulty_stages_match() {
    let mut rng = Rng(0x1f2e3d4c5b6a7988);
    for number in [
        1u32, 41999, 42000, 65535, 65536, 107000, 150000, 168000, 250000,
    ] {
        for _ in 0..20000 {
            let sha3hx = rng.hash();
            let x16rshx = rng.hash();
            let combined = check_diamond_difficulty(number, &sha3hx, &x16rshx);
            let staged = check_diamond_difficulty_sha3(number, &sha3hx)
                && check_diamond_difficulty_x16rs(number, &x16rshx);
            assert_eq!(
                combined,
                staged,
                "stage split diverged at number={} sha3={} x16rs={}",
                number,
                hex::encode(sha3hx),
                hex::encode(x16rshx)
            );
        }
    }
}

/// The SHA3 stage is a *necessary* condition, which is what makes it safe to
/// drop a nonce before running X16RS. If it fails, no X16RS digest can rescue it.
#[test]
fn t_diamond_sha3_stage_is_necessary() {
    let mut rng = Rng(0xaabbccdd11223344);
    let number = 150000u32;
    let mut rejected = 0usize;
    let total = 20000usize;
    for _ in 0..total {
        let sha3hx = rng.hash();
        if check_diamond_difficulty_sha3(number, &sha3hx) {
            continue;
        }
        rejected += 1;
        // whatever the X16RS half looks like, the diamond cannot be valid
        for _ in 0..8 {
            let x16rshx = rng.hash();
            assert!(!check_diamond_difficulty(number, &sha3hx, &x16rshx));
        }
        // not even the most favourable X16RS digest possible
        assert!(!check_diamond_difficulty(number, &sha3hx, &[0u8; 32]));
    }
    // documents the size of the prize: ~89% of nonces never need X16RS at all
    let pass_rate = 1.0 - (rejected as f64 / total as f64);
    assert!(
        pass_rate > 0.09 && pass_rate < 0.13,
        "unexpected stage-1 pass rate at diamond 150000: {:.4}",
        pass_rate
    );
}

/// The analytic pass rate has to match what the predicate actually does,
/// otherwise a miner sizing its batches from it would starve or overflow.
#[test]
fn t_diamond_sha3_gate_pass_rate() {
    let mut rng = Rng(0x77e1c3f5a90b4d26);
    for number in [1u32, 107000, 150000, 210000] {
        let predicted = diamond_sha3_gate_pass_rate(number);
        let total = 200000usize;
        let mut passed = 0usize;
        for _ in 0..total {
            if check_diamond_difficulty_sha3(number, &rng.hash()) {
                passed += 1;
            }
        }
        let observed = passed as f64 / total as f64;
        let tol = 6.0 * (predicted * (1.0 - predicted) / total as f64).sqrt() + 1e-9;
        assert!(
            (observed - predicted).abs() <= tol,
            "number={} predicted={:.5} observed={:.5}",
            number,
            predicted,
            observed
        );
    }
    // the gate must never claim to keep everything once difficulty has ramped
    assert!(diamond_sha3_gate_pass_rate(150000) < 0.15);
    assert_eq!(diamond_sha3_gate_pass_rate(1), 1.0);
}

/// mine_diamond must stay exactly the composition of its two halves.
#[test]
fn t_mine_diamond_stages_match() {
    let mut rng = Rng(0x0102030405060708);
    let address = [2u8; 21];
    for number in [20001u32, 107000, 150000] {
        for _ in 0..64 {
            let prev = rng.hash();
            let msg = rng.hash();
            let nonce: [u8; 8] = rng.next().to_be_bytes();
            let (sha3hx, x16rshx, name) = mine_diamond(number, &prev, &nonce, &address, &msg);
            let staged_sha3 = mine_diamond_sha3(&prev, &nonce, &address, &msg);
            let (staged_x16rs, staged_name) = mine_diamond_x16rs(number, &staged_sha3);
            assert_eq!(sha3hx, staged_sha3);
            assert_eq!(x16rshx, staged_x16rs);
            assert_eq!(name, staged_name);
        }
    }
}

#[test]
fn t_shas() {
    // sha2
    let cres = hex::encode(sha2("123456"));
    assert_eq!(
        cres,
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    );

    // sha3
    let cres = hex::encode(sha3("123456"));
    assert_eq!(
        cres,
        "d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e"
    );

    /*
    genesis block head meta:
    01
    0000000000
    005c57b08c
    0000000000000000000000000000000000000000000000000000000000000000
    ad557702fc70afaf70a855e7b8a4400159643cb5a7fc8a89ba2bce6f818a9b01
    00000001
    098b3445
    00000000
    0000
    */
    // block_hash
    let hdts = hex::decode("010000000000005c57b08c0000000000000000000000000000000000000000000000000000000000000000ad557702fc70afaf70a855e7b8a4400159643cb5a7fc8a89ba2bce6f818a9b0100000001098b3445000000000000").unwrap();
    let cres = hex::encode(block_hash(1, &hdts));
    assert_eq!(
        cres,
        "000000077790ba2fcdeaef4a4299d9b667135bac577ce204dee8388f1b97f7e6"
    );
}
