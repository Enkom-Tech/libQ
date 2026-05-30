path = r"c:\Users\Xtreme-W\Transfer\Enkom\Enkom\Git\libQ\lib-q-hqc\tests\kat_test.rs"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

out = []
i = 0
while i < len(lines) and (lines[i].startswith("//!") or lines[i].strip() == ""):
    out.append(lines[i])
    i += 1

mod_idx = None
for j, line in enumerate(lines):
    if line.strip() == "mod hqc1_kat_vectors {":
        mod_idx = j
        break
assert mod_idx is not None

inner_lines = lines[mod_idx + 1 : -1]
filtered = []
skip_next_blank = False
for ln in inner_lines:
    if ln.strip() == "use super::*;":
        skip_next_blank = True
        continue
    if skip_next_blank and ln.strip() == "":
        skip_next_blank = False
        continue
    skip_next_blank = False
    filtered.append(ln)

new_filtered = []
idx = 0
while idx < len(filtered):
    if (
        idx + 1 < len(filtered)
        and filtered[idx].strip() == "#[test]"
        and filtered[idx + 1].strip() == '#[cfg(feature = "bearssl-aes")]'
    ):
        new_filtered.append(filtered[idx])
        idx += 2
        continue
    new_filtered.append(filtered[idx])
    idx += 1
filtered = new_filtered

indented_inner = []
for ln in filtered:
    if ln.strip() == "":
        indented_inner.append(ln)
    else:
        indented_inner.append("    " + ln)

bearssl = """#[cfg(feature = "bearssl-aes")]
mod bearssl_kat {
    use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
    use lib_q_hqc::hqc_kem::HqcKem;
    use lib_q_hqc::*;
    use rand_core::Rng;

    /// Parse hex string to bytes
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut chars = hex.chars().peekable();

        while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
            let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
            bytes.push(byte);
        }

        bytes
    }

    /// Test vector from official NIST KAT files (HQC-1, count=0)
    /// From: lib-q-hqc/kats/official/hqc-1/PQCkemKAT_2321.rsp
    mod hqc1_kat_vectors {
"""

out.append(bearssl)
out.extend(indented_inner)
out.append("    }\n")
out.append("}\n")

with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.writelines(out)
