//! Fixture: planted always-false feature gates, plus controls that must NOT be reported.
//! Every line number here is asserted by EXPECTED.txt -- adding a line shifts the expectations.

// PLANTED 1: multi-line attribute. A line-oriented scanner misses this.
#[cfg(
    feature = "ghost_multiline"
)]
pub fn planted_multiline() {}

// PLANTED 2: the cfg! expression macro rather than the attribute form.
pub fn planted_macro() -> bool {
    cfg!(feature = "ghost_macro")
}

// PLANTED 3: nested inside a combinator.
#[cfg(all(unix, feature = "ghost_nested"))]
pub fn planted_nested() {}

// PLANTED 4: optional dep suppressed by `dep:` syntax, so no implicit feature exists.
#[cfg(feature = "serde")]
pub fn planted_dep_syntax() {}

// CONTROL: a real feature.
#[cfg(feature = "real")]
pub fn control_real() {}

// CONTROL: implicit feature from an optional dependency not named with `dep:`.
#[cfg(feature = "rand")]
pub fn control_implicit_optional_dep() {}

// CONTROL: a CPU feature, never declared in [features].
#[cfg(target_feature = "avx2")]
pub fn control_target_feature() {}

// CONTROL: the documented escape hatch.
#[cfg(feature = "deliberately_undefined")] // feature-gate-ok: fixture control
pub fn control_exempted() {}

// CONTROL: a char literal holding a double quote must not desynchronise the string scanner --
// if it does, everything after this point stops being scanned and the planted gates above are
// the only ones found.
pub fn control_quote_char() -> char {
    '"'
}

// CONTROL: a commented-out gate, placed directly after the char literal above and with no other
// double-quote character in between. Comments are stripped before scanning, so this must never
// be reported:  #[cfg(feature = "ghost_in_a_comment")]
//
// It is what makes the char-literal handling load-bearing. If a quote inside a char literal
// desynchronises the string scanner, the scanner treats everything up to the next quote as
// string content and stops stripping comments through that region -- so this commented-out gate
// gets read as real code and reported. Verified: breaking char-literal handling turns this line
// into an UNEXPECTED entry in the self-test.
//
// Note the failure direction. Strings are deliberately preserved rather than blanked (the guard
// needs the feature name out of them), so the damage here is a FALSE POSITIVE, not a missed
// gate. An earlier draft of this fixture asserted the opposite and its control could not fail.

// PLANTED 7: after all of the above, to confirm scanning still reaches end-of-file.
#[cfg(feature = "ghost_after_char_literal")]
pub fn planted_after_char_literal() {}

// CONTROL: cfg_attr's SECOND argument is an attribute, not a condition, so a `feature = ` string
// appearing there must NOT be reported -- only the first argument is a cfg condition.
//
// The payload is a RAW string on purpose. An earlier draft escaped the inner quotes
// (`doc = "feature = \"x\""`), which meant the payload could never match the feature pattern
// under any implementation, so the control passed whether or not the first-argument logic
// existed. Raw-string form removes the escapes and makes it load-bearing: scanning the payload
// now reports `not_a_condition` as an UNEXPECTED finding.
#[cfg_attr(feature = "real", doc = r#"feature = "not_a_condition""#)]
pub fn control_cfg_attr_payload() {}
