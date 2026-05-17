use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use lib_q_hqc::{
    Hqc1Params,
    HqcParams,
};
use rand_core::Rng;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars().peekable();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

#[test]
fn analyze_vect_set_random_differences() {
    // Real KAT test vector from PQCkemKAT_2321.rsp
    let seed = "9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505";
    let expected_h_hex = "86fd1416f12a3a12a3cdcff1fed3a13172a551ae2eebb2164ffd327c17b428cb3a3d4a8b04680f0fa3ed99cba5747dc16dd25edb4d249ac09c6a81289e82cbde074a0e1ed8ca3ced14c1a243fc9721cd5964199fde66d1407f839ab2209a6282d4b9d7f5abac0ad544987444e4d820c86f47d16841af17a159603ffb39803d7a8f0d0ec145c2637a74ad25752818e4f91ff8c65e855ce2047a3ee50176d12f79483cdfab1ea10029f2210fb12f021151a3e71c2968a948c635e1709f817658b2adff1079eaefe9fea75f6710031bed97574eae1bc41363376d18c73d7282bd58113b461f5f8f145378204aede48416139fc2a27010b126218ec6676dccba6c5292b3e43c4b6e66cbc25cf1126e8de5a983b9850b2d1520f50e7dabe5e2d889dd61e534ca85050e94b6b4f52f094414799110f84081325a4949695685598d21746b4b8f1f16a3e7b3defc656863c679bb67d7f25b8860b87f7b8541d98b6f912f980b46632a7e6de9dfe238f935873d5560c7dd102b371e3896464288d12078032d3c0a539d0888c441ca36d6a714edfe6ef9803e80a255daa9a3220e2e80291a7fc880c55ffa2bc4111e5f50788de0688319c6d55a79f19bb34f34e3044520ce57347eeb596e0d281b154f8b43d42b1053efb47778f839adc8ce2b0c876b089403cfa572597919cc9b96bcd07ef120981b33ba67474f3e974331dbc01bb2bfe20b671cef08d416b9c50c2e4d2079cf42b581869a0a33c80518c976cf9437c29a6f16c97de04dc3d417b4fd06e4004e0051c71eedf26ec444cfd369dcc9ae3ec432eefe6cb32520fcaa44e5e528d23336e3f22f072cf1b3f61bed5204dbee64eeac682788eff9e9ae04d6031aef2fcff54eed04bf2ff4135e5bf40933fccb333337341d30a4b03c6e32c8bbc346a9e14e285334e5193524de549910e52a28fd1f2d8c665b40fda59f1f2684c7059f1f91e103a20f42c3bc657e2ab5269a67d617c592966902cc3984433ef0c196dccbb8de1934df39c673edbd65d2fa0ada08881d4b9c0aefcdf80abf1f9455d2c5b80ec30d0f300ae4f2467aadd87da7a4625ff3582026eb6cbce9ef6851f993a5580026e7850658e22a40ad7bba862c5b247883a4e73465e201dfd20581fb614845c6a3752f9391566ed601f38cae6e01fb42879d704857254a8016f7082c1f9944c12fbe90238a14ddea5fedc7a8c089c8f07c2b7bb0a886c4de6a8d09007d3c4f93d14f8c320b2124450fc6662ff4d65e7966a53a5993a0c658f83ce47127a499a1437723018eea6e1560c077cb4905c33054d613329e2f953d8108937fb92ee0debec6c4aa4ef492b19c86733a2525a142886bcaea7b115ea70a2a2b897f28a596a7d82a21721e03432c4554a994aef0af8193234949b1dfef86e80041951dc7f5e304720cc8278b3ee31f107a041485d8edebc6d8481614b9e586b07c712c6ece5eef582735fa9b35e7e16bfe49d7bf8c09a2459bc8cb31fd409b1e10c0fcb348c09283781ce1d5bb4a8f5ad274de60ab420b731afdb174374d295b99c0605b3002b3c8d04770a3e24643af99478f2540a4c6ee1de065e71c168833a0c1ba9d5d1cb29e3883cc056ec0d4dffaf6bb2fc82bfb069a5f0bc8e5462699fb68965a2ed64158332770de1d01be43ea74702728637e9eba4c69e534f282e3d52b66625a9a435122af8945c477b99d7358f9523b75f4aff946d41c7e8e754e5f689e0f23d4352511105b5609a9ec57da69cc4796ea4523cd624ab460146619b0b86ba7094910e83accf2f6e347f91c736d4890746cd6ca19bfa6e2457e4d66b6a6781fe0ea43db78b55934dcb34b37ba2dd90854683c6f4ba1e6a92df8c7d2d62eb1b820596ed5a6957cc9463f32a3a9e81fa3679aeb2f8dd2ec55169b18854da2e2a3c7611ff7184dd06aeda05ba2e65fcbf44f2954c299019dea3ebdc897d40f78a99a66849c9a7752f035a3c6d43305e40f77a3a3fcee157330f53eb04fd328d862ee98ce15964a30c1d8c53dfa0608f5e18db387be9aa0847aed8a0a99e698783ba0cbe867d4cc3c074c88c9c0ef18278b910ae763167720595644b07178c341d8d2570a820a00c1cfccf4523d59cc8cebcff57ad46e1eaeb26a27c93a60798e787127a1229e7d069fbf8ae4c2cf2e4fe9c04e508e9d868ea67908a5fb4f08b02c219a90d2d81e0ca32dbbb0c3db53a26951511a725d5f8c2a2ebcca867fb8dcae1fd5de96eab04af75597dcf1b1fff6d4d501a8e0a3e8218dde4c815c7b3683444e9a758940883fde65a42f87484b2f06702cbcab1f0d58d0f38c6ce61b5a2adc7230e0f4033721c9c04edc6e4af517b9c1438a359d4515fabbd7725debdac642f198f0a4c014b4af83498264cc1ce5e3c8458f38f4d9187a21eaaa6c591ffc83050897ae6903a3c7a52b8767574bc40b12f02e8dd45aeb560451ece46243c57edac60b9bf32e698d3393a2ad1d96c5e8aaea9c7dc746da595dc42e8cf608779c2b6711c2f81fc22215b39a3fe45046dd7f5faec520326251bd30c57d06cec2693a44645d2d797fe5052b115f119a2b51d0abdd00c635764f312f3e4fff44f625deb48d096e301981ea782c1ac2f3795888c3c7dcd4913ce268d0df5c81ccee1fafa5315f03ab1a944c9a7affbcbfec2975b6f77a8f3e19b27d30edf246e4c0fea0a70d4a53d0f457c394fded6936fc0bd5ec7735e4afb21c1271fc650dc7c49bf6c51286170c208e339aaf77decc4874ba646221883d3796a6edf481ab9faa14d46560d38593a7b9087e5e33f7483fe6d63957e6c8b3165630f8264fac6e41d06bc660af2027e086da098ca07d67064419b2abf07475d015a71128e24e74510386025ffa0bfa938344971d6d6c108a0624e0f57456e76b3672d0631c6a81620f75dcf8ad202159aab00ce51307034a4f0a19ad7f9875c0d84c9c8f49842501fff6fdc6f309d56003e177992a20c71f26d839ec751386878566bfb96524fd1511bd278d3904ef3b9475fb97dabb22eaa9c5266cfa40a218308eae4d88444dedfe1e6e4bbec71144911063d91b813e1193fecc19287c2d112368b45336caf15f90fa7b325440b75f23568480dc597353d1bb01";

    let seed_bytes = hex_to_bytes(seed);
    let expected_h = hex_to_bytes(expected_h_hex);

    // Create SHAKE256 PRNG with test seed for KAT compatibility (matches reference implementation)
    let mut entropy_input = [0u8; 48];
    entropy_input.copy_from_slice(&seed_bytes[..48]);
    let mut rng = create_shake256_prng_rng(entropy_input);

    // Get seed_kem from PRNG (same as KAT test)
    let mut seed_kem = [0u8; 32];
    rng.fill_bytes(&mut seed_kem);

    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    // Test vect_set_random directly with the same seed_ek that should generate h
    let seed_ek = "ef2b80f46f3a6437b4d869bb38bdd6004bff72bcd0ceb139b4b8d47301f4fcb1";
    let seed_ek_bytes = hex_to_bytes(seed_ek);

    // Create XOF with seed_ek and domain separation for h generation (domain 1, like in keygen)
    let mut xof = lib_q_hqc::internal::shake256::Shake256Xof::new();
    xof.init_with_domain(&seed_ek_bytes, 1).unwrap();

    // Generate h vector using our vect_set_random
    let mut h = vec![0u64; Hqc1Params::VEC_N_SIZE_64];
    pke.vect_set_random(&mut xof, &mut h).unwrap();

    // Convert h to bytes for comparison
    let mut h_bytes = vec![0u8; h.len() * 8];
    for (i, word) in h.iter().enumerate() {
        let bytes = word.to_le_bytes();
        h_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    println!("=== VECT_SET_RANDOM ANALYSIS ===");
    println!("Expected h (first 32 bytes): {:02x?}", &expected_h[0..32]);
    println!("Actual h   (first 32 bytes): {:02x?}", &h_bytes[0..32]);

    // Find first difference
    let mut first_diff = None;
    for (i, (exp, act)) in expected_h.iter().zip(h_bytes.iter()).enumerate() {
        if exp != act {
            first_diff = Some(i);
            break;
        }
    }

    if let Some(pos) = first_diff {
        println!("First difference at byte position: {}", pos);
        println!("Expected: 0x{:02X}", expected_h[pos]);
        println!("Actual:   0x{:02X}", h_bytes[pos]);

        // Show surrounding bytes for context
        let start = pos.saturating_sub(8);
        let end = std::cmp::min(pos + 8, expected_h.len());

        println!("Context (bytes {} to {}):", start, end - 1);
        println!("Expected: {:02X?}", &expected_h[start..end]);
        println!("Actual:   {:02X?}", &h_bytes[start..end]);

        // Map to u64 word index
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        println!(
            "This maps to u64 word index: {}, byte within word: {}",
            word_idx, byte_in_word
        );

        // Show the actual u64 values
        if word_idx < h.len() {
            println!(
                "Expected u64[{}]: 0x{:016X}",
                word_idx,
                u64::from_le_bytes([
                    expected_h[word_idx * 8],
                    expected_h[word_idx * 8 + 1],
                    expected_h[word_idx * 8 + 2],
                    expected_h[word_idx * 8 + 3],
                    expected_h[word_idx * 8 + 4],
                    expected_h[word_idx * 8 + 5],
                    expected_h[word_idx * 8 + 6],
                    expected_h[word_idx * 8 + 7],
                ])
            );
            println!("Actual u64[{}]:   0x{:016X}", word_idx, h[word_idx]);
        }
    } else {
        println!("No differences found - vect_set_random matches reference!");
    }
}
