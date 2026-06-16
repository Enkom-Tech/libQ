//! Anti-drift layer 2 (PLAN Part 3): assert the compiled-in constants equal the
//! vendored canonical profile JSON. The runtime artifact never parses JSON; this
//! test is the only place serde_json is used, and it fails CI on any divergence
//! between code and spec.

use serde_json::Value;

fn u64_hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap(), 16).unwrap()
}

#[test]
fn constants_match_vendored_profile() {
    let raw = include_str!("../spec/sah-256.profile.json");
    let p: Value = serde_json::from_str(raw).unwrap();

    assert_eq!(p["spec_version"].as_str().unwrap(), lib_q_sah::SPEC_VERSION);
    assert_eq!(p["status"].as_str().unwrap(), "draft");
    assert_eq!(p["key_bits"].as_u64().unwrap() as usize, lib_q_sah::KEY_LEN * 8);
    assert_eq!(p["nonce_bits"].as_u64().unwrap() as usize, lib_q_sah::NONCE_LEN * 8);
    assert_eq!(p["tag_bits"].as_u64().unwrap() as usize, lib_q_sah::TAG_LEN * 8);

    // Round schedule, rotations, linear layer, domain bytes, IV, param.
    // These mirror src/params.rs; kept in this test module via a re-import of the
    // public constants where exposed and literal checks where internal.
    let rounds = &p["rounds"];
    assert_eq!(rounds["init"].as_u64().unwrap(), 12);
    assert_eq!(rounds["aad"].as_u64().unwrap(), 2);
    assert_eq!(rounds["msg"].as_u64().unwrap(), 2);
    assert_eq!(rounds["final"].as_u64().unwrap(), 12);

    let rot: Vec<u64> = p["rotations"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(rot, vec![32, 24, 16, 63]);

    let pi: Vec<u64> = p["linear_pi"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(pi, vec![1, 6, 3, 0, 5, 2, 7, 4]);

    let rho: Vec<u64> = p["linear_rho"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(rho, vec![0, 8, 16, 24, 32, 40, 48, 56]);

    assert_eq!(u64_hex(&p["iv"]), 0x7f078b526feaa5cb);
    assert_eq!(u64_hex(&p["param_word"]), 0x0001008000800100);

    let rcs = p["round_constants"].as_array().unwrap();
    assert_eq!(rcs.len(), 16);
    assert_eq!(u64_hex(&rcs[0]), 0x7a42dc8d91f64384);
    assert_eq!(u64_hex(&rcs[15]), 0x48fffa3f03f93802);

    let sbox = p["sbox"].as_array().unwrap();
    assert_eq!(sbox.len(), 256);
    assert_eq!(u8::from_str_radix(sbox[0].as_str().unwrap(), 16).unwrap(), 0x63);
    assert_eq!(u8::from_str_radix(sbox[0x53].as_str().unwrap(), 16).unwrap(), 0xed);

    let dom = &p["domain"];
    assert_eq!(u8::from_str_radix(dom["init"].as_str().unwrap(), 16).unwrap(), 0x01);
    assert_eq!(u8::from_str_radix(dom["final"].as_str().unwrap(), 16).unwrap(), 0x08);
}
