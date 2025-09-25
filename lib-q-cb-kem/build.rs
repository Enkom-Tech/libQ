#[allow(clippy::disallowed_types)]
use std::collections::HashMap;

fn main() {
    #[allow(clippy::disallowed_types)]
    let mut features = HashMap::new();

    features.insert("cbkem348864", cfg!(feature = "cbkem348864"));
    features.insert("cbkem348864f", cfg!(feature = "cbkem348864f"));
    features.insert("cbkem460896", cfg!(feature = "cbkem460896"));
    features.insert("cbkem460896f", cfg!(feature = "cbkem460896f"));
    features.insert("cbkem6688128", cfg!(feature = "cbkem6688128"));
    features.insert("cbkem6688128f", cfg!(feature = "cbkem6688128f"));
    features.insert("cbkem6960119", cfg!(feature = "cbkem6960119"));
    features.insert("cbkem6960119f", cfg!(feature = "cbkem6960119f"));
    features.insert("cbkem8192128", cfg!(feature = "cbkem8192128"));
    features.insert("cbkem8192128f", cfg!(feature = "cbkem8192128f"));

    let mut target_feature = "";
    for (feature, used) in features {
        if !target_feature.is_empty() && used {
            panic!(
                "Config error: \n\t{target_feature} and {feature} cannot be used simultaneously!\n\tPlease select only one feature."
            );
        } else if used {
            target_feature = feature;
        }
    }

    if target_feature.is_empty() {
        println!("cargo:rustc-cfg=feature=\"cbkem348864\"");
    }
}
