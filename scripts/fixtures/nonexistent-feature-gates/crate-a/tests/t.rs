// PLANTED 5: under tests/, which a src/-only scanner never reaches.
#[cfg(feature = "ghost_testdir")]
#[test]
fn planted_in_tests_dir() {}
