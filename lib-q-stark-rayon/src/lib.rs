#![cfg_attr(not(feature = "parallel"), no_std)]

#[cfg(all(feature = "parallel", target_arch = "wasm32"))]
compile_error!(
    "parallel feature is not supported on wasm32; do not enable 'parallel' for WASM builds"
);

#[cfg(feature = "parallel")]
pub mod prelude {
    use core::marker::{
        Send,
        Sync,
    };

    pub use rayon::prelude::*;
    pub use rayon::{
        current_num_threads,
        join,
    };

    /// `identity()` MUST be a genuine identity element for `reduce_op`, i.e.
    /// `reduce_op(identity(), x) == x` for every reachable `x` — the same contract
    /// `rayon::iter::ParallelIterator::reduce` documents. On the real rayon backend an empty (or
    /// unevenly split) input can still route a folded `identity()` leaf back through `reduce_op`,
    /// so a non-identity "identity" silently diverges from the serial fallback (which ignores
    /// `reduce_op` and simply returns a single `identity()`-seeded fold). Confirmed divergence:
    /// with `reduce_op = |a, b| a + b` and `identity = || -7`, an empty input yields `-7` on the
    /// serial backend but `reduce_op(-7, -7) == -14` on the parallel backend.
    pub trait SharedExt: ParallelIterator {
        fn par_fold_reduce<Acc, Id, F, R>(self, identity: Id, fold_op: F, reduce_op: R) -> Acc
        where
            Acc: Send,
            Id: Fn() -> Acc + Sync + Send,
            F: Fn(Acc, Self::Item) -> Acc + Sync + Send,
            R: Fn(Acc, Acc) -> Acc + Sync + Send;
    }

    impl<I: ParallelIterator> SharedExt for I {
        #[inline]
        fn par_fold_reduce<Acc, Id, F, R>(self, identity: Id, fold_op: F, reduce_op: R) -> Acc
        where
            Acc: Send,
            Id: Fn() -> Acc + Sync + Send,
            F: Fn(Acc, Self::Item) -> Acc + Sync + Send,
            R: Fn(Acc, Acc) -> Acc + Sync + Send,
        {
            self.fold(&identity, fold_op).reduce(&identity, reduce_op)
        }
    }
}

#[cfg(feature = "parallel")]
pub mod iter {
    pub use rayon::iter::{
        repeat,
        repeat_n,
    };
}

#[cfg(not(feature = "parallel"))]
mod serial;

#[cfg(not(feature = "parallel"))]
pub mod prelude {
    pub use core::iter::{
        ExactSizeIterator as IndexedParallelIterator,
        Iterator as ParallelIterator,
    };
    use core::marker::{
        Send,
        Sync,
    };

    pub use super::serial::*;

    /// `identity()` MUST be a genuine identity element for `reduce_op`, i.e.
    /// `reduce_op(identity(), x) == x` for every reachable `x` — the same contract
    /// `rayon::iter::ParallelIterator::reduce` documents. This serial fallback ignores
    /// `reduce_op` entirely and just returns a single `identity()`-seeded fold, so it will not
    /// itself notice a violation — but the real (`parallel`-feature) rayon backend can route a
    /// folded `identity()` leaf back through `reduce_op` (e.g. on empty or unevenly split input),
    /// which silently diverges from this fallback unless the contract holds. Confirmed divergence:
    /// with `reduce_op = |a, b| a + b` and `identity = || -7`, an empty input yields `-7` here but
    /// `reduce_op(-7, -7) == -14` on the parallel backend.
    pub trait SharedExt: ParallelIterator {
        fn par_fold_reduce<Acc, Id, F, R>(self, identity: Id, fold_op: F, reduce_op: R) -> Acc
        where
            Acc: Send,
            Id: Fn() -> Acc + Sync + Send,
            F: Fn(Acc, Self::Item) -> Acc + Sync + Send,
            R: Fn(Acc, Acc) -> Acc + Sync + Send;
    }

    impl<I: ParallelIterator> SharedExt for I {
        #[inline]
        fn par_fold_reduce<Acc, Id, F, R>(self, identity: Id, fold_op: F, _reduce_op: R) -> Acc
        where
            Acc: Send,
            Id: Fn() -> Acc + Sync + Send,
            F: Fn(Acc, Self::Item) -> Acc + Sync + Send,
            R: Fn(Acc, Acc) -> Acc + Sync + Send,
        {
            self.fold(identity(), fold_op)
        }
    }
}

#[cfg(not(feature = "parallel"))]
pub mod iter {
    pub use core::iter::{
        repeat,
        repeat_n,
    };
}
