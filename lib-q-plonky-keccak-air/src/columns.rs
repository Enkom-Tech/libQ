use core::mem::size_of;

use lib_q_stark_util::indices_arr;

use crate::constants::R;
use crate::{
    NUM_ROUNDS,
    RATE_LIMBS,
    U64_LIMBS,
};

/// Note: The ordering of each array is based on the input mapping. As the spec says,
///
/// > The mapping between the bits of s and those of a is `s[w(5y + x) + z] = a[x][y][z]`.
///
/// Thus, for example, `a_prime` is stored in `y, x, z` order. This departs from the more common
/// convention of `x, y, z` order, but it has the benefit that input lists map to AIR columns in a
/// nicer way.
#[derive(Debug)]
#[repr(C)]
pub struct KeccakCols<T> {
    /// The `i`th value is set to 1 if we are in the `i`th round, otherwise 0.
    pub step_flags: [T; NUM_ROUNDS],

    /// A register which indicates if a row should be exported, i.e. included in a multiset equality
    /// argument. Should be 1 only for certain rows which are final steps, i.e. with
    /// `step_flags[23] = 1`.
    pub export: T,

    /// Permutation inputs, stored in y-major order.
    pub preimage: [[[T; U64_LIMBS]; 5]; 5],

    pub a: [[[T; U64_LIMBS]; 5]; 5],

    /// ```ignore
    /// C[x] = xor(A[x, 0], A[x, 1], A[x, 2], A[x, 3], A[x, 4])
    /// ```
    pub c: [[T; 64]; 5],

    /// ```ignore
    /// C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1])
    /// ```
    pub c_prime: [[T; 64]; 5],

    /// ```ignore
    /// A'[x, y] = xor(A[x, y], D[x])
    ///          = xor(A[x, y], C[x - 1], ROT(C[x + 1], 1))
    /// ```
    pub a_prime: [[[T; 64]; 5]; 5],

    /// ```ignore
    /// A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
    /// ```
    pub a_prime_prime: [[[T; U64_LIMBS]; 5]; 5],

    /// The bits of `A''[0, 0]`.
    pub a_prime_prime_0_0_bits: [T; 64],

    /// ```ignore
    /// A'''[0, 0, z] = A''[0, 0, z] ^ RC[k, z]
    /// ```
    pub a_prime_prime_prime_0_0_limbs: [T; U64_LIMBS],
}

impl<T: Copy> KeccakCols<T> {
    pub fn b(&self, x: usize, y: usize, z: usize) -> T {
        debug_assert!(x < 5);
        debug_assert!(y < 5);
        debug_assert!(z < 64);

        // B is just a rotation of A', so these are aliases for A' registers.
        // From the spec,
        //     B[y, (2x + 3y) % 5] = ROT(A'[x, y], r[x, y])
        // So,
        //     B[x, y] = f((x + 3y) % 5, x)
        // where f(a, b) = ROT(A'[a, b], r[a, b])
        let a = (x + 3 * y) % 5;
        let b = x;
        let rot = R[a][b] as usize;
        self.a_prime[b][a][(z + 64 - rot) % 64]
    }

    pub fn a_prime_prime_prime(&self, y: usize, x: usize, limb: usize) -> T {
        debug_assert!(y < 5);
        debug_assert!(x < 5);
        debug_assert!(limb < U64_LIMBS);

        if y == 0 && x == 0 {
            self.a_prime_prime_prime_0_0_limbs[limb]
        } else {
            self.a_prime_prime[y][x][limb]
        }
    }
}

pub fn input_limb(i: usize) -> usize {
    debug_assert!(i < RATE_LIMBS);

    let i_u64 = i / U64_LIMBS;
    let limb_index = i % U64_LIMBS;

    let y = i_u64 / 5;
    let x = i_u64 % 5;

    KECCAK_COL_MAP.preimage[y][x][limb_index]
}

pub fn output_limb(i: usize) -> usize {
    debug_assert!(i < RATE_LIMBS);

    let i_u64 = i / U64_LIMBS;
    let limb_index = i % U64_LIMBS;

    let y = i_u64 / 5;
    let x = i_u64 % 5;

    KECCAK_COL_MAP.a_prime_prime_prime(y, x, limb_index)
}

pub const NUM_KECCAK_COLS: usize = size_of::<KeccakCols<u8>>();
pub(crate) const KECCAK_COL_MAP: KeccakCols<usize> = make_col_map();

const fn make_col_map() -> KeccakCols<usize> {
    let arr = indices_arr::<NUM_KECCAK_COLS>();
    let mut step_flags = [0usize; NUM_ROUNDS];
    let mut i = 0;
    while i < NUM_ROUNDS {
        step_flags[i] = arr[i];
        i += 1;
    }
    let mut preimage = [[[0usize; U64_LIMBS]; 5]; 5];
    let mut y = 0;
    while y < 5 {
        let mut x = 0;
        while x < 5 {
            let mut limb = 0;
            while limb < U64_LIMBS {
                preimage[y][x][limb] = arr[25 + y * 5 * U64_LIMBS + x * U64_LIMBS + limb];
                limb += 1;
            }
            x += 1;
        }
        y += 1;
    }
    let mut a = [[[0usize; U64_LIMBS]; 5]; 5];
    y = 0;
    while y < 5 {
        let mut x = 0;
        while x < 5 {
            let mut limb = 0;
            while limb < U64_LIMBS {
                a[y][x][limb] = arr[125 + y * 5 * U64_LIMBS + x * U64_LIMBS + limb];
                limb += 1;
            }
            x += 1;
        }
        y += 1;
    }
    let mut c = [[0usize; 64]; 5];
    let mut x = 0;
    while x < 5 {
        let mut z = 0;
        while z < 64 {
            c[x][z] = arr[225 + x * 64 + z];
            z += 1;
        }
        x += 1;
    }
    let mut c_prime = [[0usize; 64]; 5];
    x = 0;
    while x < 5 {
        let mut z = 0;
        while z < 64 {
            c_prime[x][z] = arr[545 + x * 64 + z];
            z += 1;
        }
        x += 1;
    }
    let mut a_prime = [[[0usize; 64]; 5]; 5];
    y = 0;
    while y < 5 {
        x = 0;
        while x < 5 {
            let mut z = 0;
            while z < 64 {
                a_prime[y][x][z] = arr[865 + y * 5 * 64 + x * 64 + z];
                z += 1;
            }
            x += 1;
        }
        y += 1;
    }
    let mut a_prime_prime = [[[0usize; U64_LIMBS]; 5]; 5];
    y = 0;
    while y < 5 {
        x = 0;
        while x < 5 {
            let mut limb = 0;
            while limb < U64_LIMBS {
                a_prime_prime[y][x][limb] = arr[2465 + y * 5 * U64_LIMBS + x * U64_LIMBS + limb];
                limb += 1;
            }
            x += 1;
        }
        y += 1;
    }
    let mut a_prime_prime_0_0_bits = [0usize; 64];
    i = 0;
    while i < 64 {
        a_prime_prime_0_0_bits[i] = arr[2565 + i];
        i += 1;
    }
    let mut a_prime_prime_prime_0_0_limbs = [0usize; U64_LIMBS];
    i = 0;
    while i < U64_LIMBS {
        a_prime_prime_prime_0_0_limbs[i] = arr[2629 + i];
        i += 1;
    }
    KeccakCols {
        step_flags,
        export: arr[24],
        preimage,
        a,
        c,
        c_prime,
        a_prime,
        a_prime_prime,
        a_prime_prime_0_0_bits,
        a_prime_prime_prime_0_0_limbs,
    }
}

/// Safe read-only view over a row slice interpreted as Keccak columns.
#[derive(Clone, Copy)]
pub struct KeccakColsRef<'a, T> {
    data: &'a [T],
}

impl<'a, T: Copy> KeccakColsRef<'a, T> {
    #[inline]
    pub fn new(slice: &'a [T]) -> Option<Self> {
        if slice.len() == NUM_KECCAK_COLS {
            Some(Self { data: slice })
        } else {
            None
        }
    }

    /// Creates a view over a row slice. Use when the slice length is guaranteed to be NUM_KECCAK_COLS (e.g. from AIR main window).
    #[inline]
    pub fn from_row_slice(slice: &'a [T]) -> Self {
        debug_assert_eq!(slice.len(), NUM_KECCAK_COLS);
        Self { data: slice }
    }

    #[inline]
    fn idx(&self, i: usize) -> T {
        self.data[i]
    }

    #[inline]
    pub fn step_flags(&self, i: usize) -> T {
        self.idx(KECCAK_COL_MAP.step_flags[i])
    }

    #[inline]
    pub fn export(&self) -> T {
        self.idx(KECCAK_COL_MAP.export)
    }

    #[inline]
    pub fn preimage(&self, y: usize, x: usize, limb: usize) -> T {
        self.idx(KECCAK_COL_MAP.preimage[y][x][limb])
    }

    #[inline]
    pub fn a(&self, y: usize, x: usize, limb: usize) -> T {
        self.idx(KECCAK_COL_MAP.a[y][x][limb])
    }

    #[inline]
    pub fn c(&self, x: usize, z: usize) -> T {
        self.idx(KECCAK_COL_MAP.c[x][z])
    }

    #[inline]
    pub fn c_prime(&self, x: usize, z: usize) -> T {
        self.idx(KECCAK_COL_MAP.c_prime[x][z])
    }

    #[inline]
    pub fn a_prime(&self, y: usize, x: usize, z: usize) -> T {
        self.idx(KECCAK_COL_MAP.a_prime[y][x][z])
    }

    #[inline]
    pub fn a_prime_prime(&self, y: usize, x: usize, limb: usize) -> T {
        self.idx(KECCAK_COL_MAP.a_prime_prime[y][x][limb])
    }

    #[inline]
    pub fn a_prime_prime_0_0_bits(&self, i: usize) -> T {
        self.idx(KECCAK_COL_MAP.a_prime_prime_0_0_bits[i])
    }

    #[inline]
    pub fn a_prime_prime_prime_0_0_limbs(&self, limb: usize) -> T {
        self.idx(KECCAK_COL_MAP.a_prime_prime_prime_0_0_limbs[limb])
    }

    pub fn b(&self, x: usize, y: usize, z: usize) -> T {
        let a = (x + 3 * y) % 5;
        let b = x;
        let rot = R[a][b] as usize;
        self.a_prime(b, a, (z + 64 - rot) % 64)
    }

    pub fn a_prime_prime_prime(&self, y: usize, x: usize, limb: usize) -> T {
        if y == 0 && x == 0 {
            self.a_prime_prime_prime_0_0_limbs(limb)
        } else {
            self.a_prime_prime(y, x, limb)
        }
    }
}

/// Safe mutable view over a row slice interpreted as Keccak columns.
pub struct KeccakColsRefMut<'a, T> {
    data: &'a mut [T],
}

impl<'a, T: Copy> KeccakColsRefMut<'a, T> {
    #[inline]
    pub fn new(slice: &'a mut [T]) -> Option<Self> {
        if slice.len() == NUM_KECCAK_COLS {
            Some(Self { data: slice })
        } else {
            None
        }
    }

    #[inline]
    fn set_idx(&mut self, i: usize, value: T) {
        self.data[i] = value;
    }

    #[inline]
    pub fn set_step_flag(&mut self, i: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.step_flags[i], value);
    }

    #[inline]
    pub fn set_export(&mut self, value: T) {
        self.set_idx(KECCAK_COL_MAP.export, value);
    }

    #[inline]
    pub fn set_preimage(&mut self, y: usize, x: usize, limb: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.preimage[y][x][limb], value);
    }

    #[inline]
    pub fn set_a(&mut self, y: usize, x: usize, limb: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.a[y][x][limb], value);
    }

    #[inline]
    pub fn set_c(&mut self, x: usize, z: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.c[x][z], value);
    }

    #[inline]
    pub fn set_c_prime(&mut self, x: usize, z: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.c_prime[x][z], value);
    }

    #[inline]
    pub fn set_a_prime(&mut self, y: usize, x: usize, z: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.a_prime[y][x][z], value);
    }

    #[inline]
    pub fn set_a_prime_prime(&mut self, y: usize, x: usize, limb: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.a_prime_prime[y][x][limb], value);
    }

    #[inline]
    pub fn set_a_prime_prime_0_0_bits(&mut self, i: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.a_prime_prime_0_0_bits[i], value);
    }

    #[inline]
    pub fn set_a_prime_prime_prime_0_0_limbs(&mut self, limb: usize, value: T) {
        self.set_idx(KECCAK_COL_MAP.a_prime_prime_prime_0_0_limbs[limb], value);
    }
}
