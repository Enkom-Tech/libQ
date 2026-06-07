#![cfg(feature = "fhe")]

use lib_q_blind_pcs::{
    blind_commit,
    blind_open,
    verify,
};
use lib_q_fhe::{
    EvalOp,
    decrypt,
    encrypt,
    eval,
    fhe_keygen,
};

#[test]
fn encrypt_commit_eval_verify_pipeline() {
    let sk = fhe_keygen(42, 4, 257);
    let plaintext = [1, 2, 3, 4];

    let ciphertext = encrypt(&sk, &plaintext, 88);
    let ciphertext_bytes = ciphertext.to_bytes();

    let blind = b"integration-blind";
    let commitment = blind_commit(&ciphertext_bytes, blind);
    let opening = blind_open(&ciphertext_bytes, blind);

    let evaluated = eval(&ciphertext, EvalOp::MulConstant(3));
    let recovered = decrypt(&sk, &evaluated);

    assert!(verify(&commitment, &opening));
    assert_eq!(recovered, vec![3, 6, 9, 12]);
}
