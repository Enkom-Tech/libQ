// PLANTED 7: a crate whose directory matches no naming convention. The scratch probe this guard
// replaced globbed `lib-q-*/` and never saw crates like this one.
#[cfg(feature = "ghost_nonlibq")]
pub fn planted_outside_naming_convention() {}
