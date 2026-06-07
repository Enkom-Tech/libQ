mod common;

use lib_q_double_kem::{
    MaulProfileV1,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
    double_decap,
    double_encap,
};

#[test]
fn wire_roundtrip_and_shared_secret_match() {
    let profile = MaulProfileV1;
    let (dk_a, ek_a, dk_b, ek_b) = common::kat_keys();
    let mut rng = common::kat_rng();

    let (wire, ss_send) = double_encap(profile, &ek_a, &ek_b, &mut rng).expect("encapsulation");
    let encoded = wire.to_bytes();
    assert_eq!(encoded.len(), WIRE_BUDGET_MAUL_ENCAP_BYTES);

    let decoded = lib_q_double_kem::MaulEncapWire::from_bytes(&encoded).expect("decode");
    let ss_recv = double_decap(profile, &decoded, &dk_a, &dk_b).expect("decapsulation");
    assert_eq!(ss_send, ss_recv);
}
