#![cfg(feature = "alloc")]
#![cfg(not(target_arch = "wasm32"))]

use std::ops::Deref;

use hex_literal::hex;
use lib_q_slh_dsa::{Shake128s, SigningKey, VerifyingKey};
use pkcs8::der::Decode;
use pkcs8::{
    DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding, ObjectIdentifier,
    PrivateKeyInfoRef,
};

// The draft-ietf-lamps-x509-slhdsa repository publishes PKCS#8 / SPKI vectors only for
// SLH-DSA-SHA2-128s, and lib-Q ships no SHA-2 parameter sets. So this test checks the encoding
// structurally instead of against a published PEM: the OID must be the NIST-registered
// id-slh-dsa-shake-128s (2.16.840.1.101.3.4.3.26, written out here rather than taken from the
// crate), the private key OCTET STRING must be the raw FIPS 205 key bytes, and both the private
// and public encodings must round-trip.
const ID_SLH_DSA_SHAKE_128S: &str = "2.16.840.1.101.3.4.3.26";

#[test]
fn pkcs8_output() {
    let raw = hex!(
        "A2263BCA45860836523160049523D621677FAD90D51EB6067A327E0D1E64A5012B8109EC777CAA4E1F024CCFCF9497D99180509280F4256AF2B07AF80289B494"
    );
    let signing = SigningKey::<Shake128s>::try_from(&raw[..]).unwrap();

    let der = signing.to_pkcs8_der().unwrap();
    let info = PrivateKeyInfoRef::from_der(der.as_bytes()).unwrap();
    assert_eq!(
        info.algorithm.oid,
        ObjectIdentifier::new_unwrap(ID_SLH_DSA_SHAKE_128S)
    );
    assert!(info.algorithm.parameters.is_none());
    assert_eq!(info.private_key.as_bytes(), &raw[..]);

    let pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
    let parsed = SigningKey::<Shake128s>::from_pkcs8_pem(pem.deref()).unwrap();
    assert_eq!(parsed, signing);

    let public: VerifyingKey<Shake128s> = parsed.as_ref().clone();
    let spki_der = public.to_public_key_der().unwrap();
    let spki = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(spki_der.as_bytes()).unwrap();
    assert_eq!(
        spki.algorithm.oid,
        ObjectIdentifier::new_unwrap(ID_SLH_DSA_SHAKE_128S)
    );
    // The public key is PK.seed || PK.root, the second half of the FIPS 205 secret key.
    assert_eq!(spki.subject_public_key.raw_bytes(), &raw[32..]);
}
