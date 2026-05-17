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
    let mut enabled_features = Vec::new();

    for (feature, used) in features {
        if used {
            enabled_features.push(feature);
            if target_feature.is_empty() {
                target_feature = feature;
            }
        }
    }

    // If multiple features are enabled (e.g., with --all-features),
    // select a default variant instead of panicking
    if enabled_features.len() > 1 {
        // Priority order: prefer smaller variants first
        let priority_order = [
            "cbkem348864",
            "cbkem348864f",
            "cbkem460896",
            "cbkem460896f",
            "cbkem6688128",
            "cbkem6688128f",
            "cbkem6960119",
            "cbkem6960119f",
            "cbkem8192128",
            "cbkem8192128f",
        ];

        for priority_feature in &priority_order {
            if enabled_features.contains(priority_feature) {
                target_feature = priority_feature;
                break;
            }
        }
    }

    if target_feature.is_empty() {
        println!("cargo:rustc-cfg=feature=\"cbkem348864\"");
    } else {
        println!("cargo:rustc-cfg=feature=\"{}\"", target_feature);
    }
}
