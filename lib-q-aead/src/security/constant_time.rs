//! Constant-time operations backed by the `subtle` crate.
//!
//! All primitives delegate to `subtle`'s `black_box`-fenced internals so the
//! compiler cannot elide the constant-time property.

pub use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

/// Constant-time byte-slice equality.
///
/// Returns `true` when `a` and `b` are identical, `false` otherwise.
/// If `a.len() != b.len()`, returns `false` immediately (standard
/// length-reveal pattern; not constant-time across differing lengths).
/// When lengths match, comparison runs in time proportional to that
/// length regardless of where (or whether) the first difference occurs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time selection: returns `a` when `condition` is `true`, `b`
/// otherwise.
pub fn constant_time_select<T: ConditionallySelectable>(condition: bool, a: T, b: T) -> T {
    T::conditional_select(&b, &a, Choice::from(condition as u8))
}

/// Constant-time boolean selection (convenience wrapper — `bool` does not
/// implement `ConditionallySelectable`).
pub fn constant_time_select_bool(condition: bool, a: bool, b: bool) -> bool {
    let choice = Choice::from(condition as u8);
    let r = u8::conditional_select(&(b as u8), &(a as u8), choice);
    r != 0
}

/// Constant-time conditional copy: copies `src` into `dst` when
/// `condition` is `true`, leaves `dst` unchanged otherwise.
///
/// If `src.len() != dst.len()`, does nothing in release builds. In debug
/// builds, `debug_assert_eq!(src.len(), dst.len())` panics so length misuse
/// is caught during development.
pub fn constant_time_copy(condition: bool, src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len(), "constant_time_copy length mismatch");
    if src.len() != dst.len() {
        return;
    }
    let choice = Choice::from(condition as u8);
    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = u8::conditional_select(d, s, choice);
    }
}

/// Constant-time conditional zero: zeroes `data` when `condition` is
/// `true`, leaves it unchanged otherwise.
pub fn constant_time_zero(condition: bool, data: &mut [u8]) {
    let choice = Choice::from(condition as u8);
    for byte in data.iter_mut() {
        *byte = u8::conditional_select(byte, &0, choice);
    }
}

/// Constant-time conditional swap: swaps `a` and `b` when `condition` is
/// `true`, leaves them unchanged otherwise.
pub fn constant_time_swap<T: ConditionallySelectable>(condition: bool, a: &mut T, b: &mut T) {
    T::conditional_swap(a, b, Choice::from(condition as u8));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 42u8, 24u8), 42);
        assert_eq!(constant_time_select(false, 42u8, 24u8), 24);
        assert_eq!(constant_time_select(true, 1u64, 0u64), 1);
        assert_eq!(constant_time_select(false, 1u64, 0u64), 0);
    }

    #[test]
    fn test_constant_time_select_bool() {
        assert!(constant_time_select_bool(true, true, false));
        assert!(!constant_time_select_bool(false, true, false));
        assert!(!constant_time_select_bool(true, false, true));
    }

    #[test]
    fn test_constant_time_copy() {
        let src = [1, 2, 3, 4];
        let mut dst = [0, 0, 0, 0];
        constant_time_copy(true, &src, &mut dst);
        assert_eq!(dst, src);

        let mut dst2 = [5, 6, 7, 8];
        constant_time_copy(false, &src, &mut dst2);
        assert_eq!(dst2, [5, 6, 7, 8]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "constant_time_copy length mismatch")]
    fn test_constant_time_copy_length_mismatch_panics_in_debug() {
        let src = [1, 2, 3, 4];
        let mut dst = [9, 9, 9];
        constant_time_copy(true, &src, &mut dst);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_constant_time_copy_length_mismatch_is_noop_in_release() {
        let src = [1, 2, 3, 4];
        let mut dst = [9, 9, 9];
        constant_time_copy(true, &src, &mut dst);
        assert_eq!(dst, [9, 9, 9]);
    }

    #[test]
    fn test_constant_time_zero() {
        let mut data = [1, 2, 3, 4];
        constant_time_zero(true, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);

        let mut data2 = [1, 2, 3, 4];
        constant_time_zero(false, &mut data2);
        assert_eq!(data2, [1, 2, 3, 4]);
    }

    #[test]
    fn test_constant_time_swap() {
        let mut a = 42u8;
        let mut b = 24u8;
        constant_time_swap(true, &mut a, &mut b);
        assert_eq!(a, 24);
        assert_eq!(b, 42);

        let mut c = 10u8;
        let mut d = 20u8;
        constant_time_swap(false, &mut c, &mut d);
        assert_eq!(c, 10);
        assert_eq!(d, 20);
    }
}
