//! Value-level Poseidon2 permutation over BabyBear, width `t = 16`.
//!
//! This is the **deployed Plonky3 / SP1 instance**: `R_F = 8` external rounds
//! (4 initial + 4 terminal), `R_P = 13` internal rounds, S-box `x^7` (`alpha = 7`).
//! Round constants are Grain-LFSR generated (`field_type=1, alpha=7, n=31, t=16,
//! R_F=8, R_P=13`) and are transcribed verbatim from Plonky3
//! `baby-bear/src/poseidon2.rs` via `tools/gen_poseidon2_ref.py` (which parses
//! them straight from that source file — no manual re-typing).
//!
//! Algorithm (also transcribed from Plonky3 `poseidon2/src/{external,internal}.rs`):
//!   permute = external_initial ; internal ; external_terminal, where
//!   - external_initial: apply the external linear layer `M_E`, then for each of
//!     the 4 initial round-constant rows: `state[i] += rc[i]; state[i] = state[i]^7`
//!     for all `i`; then apply `M_E`.
//!   - internal: for each of the 13 internal constants: `state[0] += rc;
//!     state[0] = state[0]^7`; then `state -> (1 + diag(V)) state`.
//!   - external_terminal: same shape as external_initial but with the terminal
//!     constants (and no leading `M_E`).
//!
//! The external `M_E` is the block-circulant matrix built from
//! `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`; the internal diagonal is
//! `V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8,
//! -1/16, -1/2^27]`. Both linear layers are algebraically cross-checked against
//! their matrix forms in `tools/gen_poseidon2_ref.py`.
//!
//! Validation level (see `lib-q-zkp/docs/membership-arm-b-build-status.md`):
//! the KAT below pins outputs produced by an INDEPENDENT Python reimplementation
//! of this same algorithm + constants. It is NOT a third-party upstream-binary
//! KAT (executing upstream Plonky3 was blocked by policy) — a documented open item.

use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::PrimeCharacteristicRing;

/// Permutation width (state size in field cells).
pub const WIDTH: usize = 16;
/// Half the number of full (external) rounds; `R_F = 2 * HALF_FULL_ROUNDS = 8`.
pub const HALF_FULL_ROUNDS: usize = 4;
/// Number of partial (internal) rounds, `R_P`.
pub const PARTIAL_ROUNDS: usize = 13;
/// S-box exponent `alpha` (BabyBear permutation monomial).
pub const SBOX_DEGREE: u64 = 7;

// ---- Round constants (canonical form; `new` converts to Montgomery). ----
// Emitted by tools/gen_poseidon2_ref.py from Plonky3 baby-bear/src/poseidon2.rs.

const RC_EXTERNAL_INITIAL: [[BabyBear; 16]; 4] = [
    [BabyBear::new(1774958255), BabyBear::new(1185780729), BabyBear::new(1621102414), BabyBear::new(1796380621), BabyBear::new(588815102), BabyBear::new(1932426223), BabyBear::new(1925334750), BabyBear::new(747903232), BabyBear::new(89648862), BabyBear::new(360728943), BabyBear::new(977184635), BabyBear::new(1425273457), BabyBear::new(256487465), BabyBear::new(1200041953), BabyBear::new(572403254), BabyBear::new(448208942)],
    [BabyBear::new(1215789478), BabyBear::new(944884184), BabyBear::new(953948096), BabyBear::new(547326025), BabyBear::new(646827752), BabyBear::new(889997530), BabyBear::new(1536873262), BabyBear::new(86189867), BabyBear::new(1065944411), BabyBear::new(32019634), BabyBear::new(333311454), BabyBear::new(456061748), BabyBear::new(1963448500), BabyBear::new(1827584334), BabyBear::new(1391160226), BabyBear::new(1348741381)],
    [BabyBear::new(88424255), BabyBear::new(104111868), BabyBear::new(1763866748), BabyBear::new(79691676), BabyBear::new(1988915530), BabyBear::new(1050669594), BabyBear::new(359890076), BabyBear::new(573163527), BabyBear::new(222820492), BabyBear::new(159256268), BabyBear::new(669703072), BabyBear::new(763177444), BabyBear::new(889367200), BabyBear::new(256335831), BabyBear::new(704371273), BabyBear::new(25886717)],
    [BabyBear::new(51754520), BabyBear::new(1833211857), BabyBear::new(454499742), BabyBear::new(1384520381), BabyBear::new(777848065), BabyBear::new(1053320300), BabyBear::new(1851729162), BabyBear::new(344647910), BabyBear::new(401996362), BabyBear::new(1046925956), BabyBear::new(5351995), BabyBear::new(1212119315), BabyBear::new(754867989), BabyBear::new(36972490), BabyBear::new(751272725), BabyBear::new(506915399)],
];

const RC_EXTERNAL_FINAL: [[BabyBear; 16]; 4] = [
    [BabyBear::new(1922082829), BabyBear::new(1870549801), BabyBear::new(1502529704), BabyBear::new(1990744480), BabyBear::new(1700391016), BabyBear::new(1702593455), BabyBear::new(321330495), BabyBear::new(528965731), BabyBear::new(183414327), BabyBear::new(1886297254), BabyBear::new(1178602734), BabyBear::new(1923111974), BabyBear::new(744004766), BabyBear::new(549271463), BabyBear::new(1781349648), BabyBear::new(542259047)],
    [BabyBear::new(1536158148), BabyBear::new(715456982), BabyBear::new(503426110), BabyBear::new(340311124), BabyBear::new(1558555932), BabyBear::new(1226350925), BabyBear::new(742828095), BabyBear::new(1338992758), BabyBear::new(1641600456), BabyBear::new(1843351545), BabyBear::new(301835475), BabyBear::new(43203215), BabyBear::new(386838401), BabyBear::new(1520185679), BabyBear::new(1235297680), BabyBear::new(904680097)],
    [BabyBear::new(1491801617), BabyBear::new(1581784677), BabyBear::new(913384905), BabyBear::new(247083962), BabyBear::new(532844013), BabyBear::new(107190701), BabyBear::new(213827818), BabyBear::new(1979521776), BabyBear::new(1358282574), BabyBear::new(1681743681), BabyBear::new(1867507480), BabyBear::new(1530706910), BabyBear::new(507181886), BabyBear::new(695185447), BabyBear::new(1172395131), BabyBear::new(1250800299)],
    [BabyBear::new(1503161625), BabyBear::new(817684387), BabyBear::new(498481458), BabyBear::new(494676004), BabyBear::new(1404253825), BabyBear::new(108246855), BabyBear::new(59414691), BabyBear::new(744214112), BabyBear::new(890862029), BabyBear::new(1342765939), BabyBear::new(1417398904), BabyBear::new(1897591937), BabyBear::new(1066647396), BabyBear::new(1682806907), BabyBear::new(1015795079), BabyBear::new(1619482808)],
];

const RC_INTERNAL: [BabyBear; 13] = [
    BabyBear::new(1518359488), BabyBear::new(1765533241), BabyBear::new(945325693), BabyBear::new(422793067), BabyBear::new(311365592), BabyBear::new(1311448267), BabyBear::new(1629555936), BabyBear::new(1009879353), BabyBear::new(190525218), BabyBear::new(786108885), BabyBear::new(557776863), BabyBear::new(212616710), BabyBear::new(605745517),
];

/// The internal-layer diagonal `V` (= `mat_internal_diag_m_1`), computed from the
/// documented BabyBear width-16 vector. `M_internal = 1 (all-ones) + diag(V)`.
#[inline]
fn internal_diag() -> [BabyBear; WIDTH] {
    let one = BabyBear::ONE;
    let three = BabyBear::new(3);
    let four = BabyBear::new(4);
    [
        -BabyBear::TWO,             // -2
        one,                        //  1
        BabyBear::TWO,              //  2
        one.halve(),                //  1/2
        three,                      //  3
        four,                       //  4
        -one.halve(),               // -1/2
        -three,                     // -3
        -four,                      // -4
        one.div_2exp_u64(8),        //  1/2^8
        one.div_2exp_u64(2),        //  1/4
        one.div_2exp_u64(3),        //  1/8
        one.div_2exp_u64(27),       //  1/2^27
        -one.div_2exp_u64(8),       // -1/2^8
        -one.div_2exp_u64(4),       // -1/16
        -one.div_2exp_u64(27),      // -1/2^27
    ]
}

/// S-box: `x^7` (alpha = 7), via `x^7 = (x^2)^2 * x^2 * x`.
#[inline]
fn sbox(x: BabyBear) -> BabyBear {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

/// The Poseidon2 `M4` block, applied in place (verbatim Plonky3 `apply_mat4`).
#[inline]
fn apply_mat4(x: &mut [BabyBear; 4]) {
    let t01 = x[0] + x[1];
    let t23 = x[2] + x[3];
    let t0123 = t01 + t23;
    let t01123 = t0123 + x[1];
    let t01233 = t0123 + x[3];
    x[3] = t01233 + x[0].double();
    x[1] = t01123 + x[2].double();
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

/// External linear layer `M_E`: `M4` on each 4-block, then the outer circulant
/// (add the four column-sums `sums[i % 4]`).
#[inline]
fn external_linear_layer(state: &mut [BabyBear; WIDTH]) {
    let mut c = 0;
    while c < WIDTH {
        let mut blk = [state[c], state[c + 1], state[c + 2], state[c + 3]];
        apply_mat4(&mut blk);
        state[c] = blk[0];
        state[c + 1] = blk[1];
        state[c + 2] = blk[2];
        state[c + 3] = blk[3];
        c += 4;
    }
    let mut sums = [BabyBear::ZERO; 4];
    let mut k = 0;
    while k < 4 {
        let mut j = 0;
        while j < WIDTH {
            sums[k] = sums[k] + state[j + k];
            j += 4;
        }
        k += 1;
    }
    let mut i = 0;
    while i < WIDTH {
        state[i] = state[i] + sums[i % 4];
        i += 1;
    }
}

/// Internal linear layer: `state[i] -> V[i] * state[i] + sum(state)`.
#[inline]
fn internal_linear_layer(state: &mut [BabyBear; WIDTH], diag: &[BabyBear; WIDTH]) {
    let mut sum = BabyBear::ZERO;
    for s in state.iter() {
        sum = sum + *s;
    }
    for i in 0..WIDTH {
        state[i] = diag[i] * state[i] + sum;
    }
}

/// The full width-16 Poseidon2 permutation over BabyBear.
pub fn permute(mut state: [BabyBear; WIDTH]) -> [BabyBear; WIDTH] {
    let diag = internal_diag();

    // Initial external linear layer.
    external_linear_layer(&mut state);

    // Initial full rounds.
    for rc in RC_EXTERNAL_INITIAL.iter() {
        for i in 0..WIDTH {
            state[i] = sbox(state[i] + rc[i]);
        }
        external_linear_layer(&mut state);
    }

    // Internal (partial) rounds.
    for &rc in RC_INTERNAL.iter() {
        state[0] = sbox(state[0] + rc);
        internal_linear_layer(&mut state, &diag);
    }

    // Terminal full rounds.
    for rc in RC_EXTERNAL_FINAL.iter() {
        for i in 0..WIDTH {
            state[i] = sbox(state[i] + rc[i]);
        }
        external_linear_layer(&mut state);
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr(v: [u32; 16]) -> [BabyBear; 16] {
        v.map(BabyBear::new)
    }

    /// KAT vs the independent Python reference (tools/gen_poseidon2_ref.py),
    /// deployed Grain-LFSR constants. See module docs for validation level.
    #[test]
    fn kat_file_random_input() {
        let input = arr([
            894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831,
            120589055, 19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920,
            1783754913,
        ]);
        let expected = arr([
            516096821, 90309867, 1101817252, 1660784290, 360715097, 1789519026, 1788910906,
            563338433, 319524748, 1741414159, 1650859320, 894311162, 1121347488, 1692793758,
            1052633829, 1344246938,
        ]);
        assert_eq!(permute(input), expected);
    }

    #[test]
    fn kat_iota_input() {
        let input = arr([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected = arr([
            1906786279, 1737026427, 1959749225, 700325316, 1638050605, 1021608788, 1726691001,
            1761127344, 1552405120, 417318995, 36799261, 1215172152, 614923223, 1300746575,
            957311597, 304856115,
        ]);
        assert_eq!(permute(input), expected);
    }

    #[test]
    fn kat_all_ones_input() {
        let input = arr([1; 16]);
        let expected = arr([
            1607442146, 1676863504, 74171774, 1027473481, 903407411, 908950222, 104477602,
            2007030265, 446104774, 602432596, 534407330, 1149883704, 1005849640, 1234792612,
            1595133452, 176734963,
        ]);
        assert_eq!(permute(input), expected);
    }

    /// Sanity: a single changed input cell perturbs the whole output (diffusion).
    #[test]
    fn diffusion_smoke() {
        let mut a = arr([0; 16]);
        let out_a = permute(a);
        a[7] = BabyBear::new(1);
        let out_b = permute(a);
        assert_ne!(out_a, out_b);
        // every output cell should differ with overwhelming probability
        let same = out_a.iter().zip(out_b.iter()).filter(|(x, y)| x == y).count();
        assert!(same <= 1, "insufficient diffusion: {same} cells unchanged");
    }
}
