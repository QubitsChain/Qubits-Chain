use fips204::ml_dsa_65;
use fips204::traits::{SerDes as _, Verifier as _};
use fips205::slh_dsa_sha2_192s;
use fips205::traits::{SerDes as _, Verifier as _};

struct Case {
    line: usize,
    valid: bool,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
    context: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn cases(file: &str) -> Vec<Case> {
    file.lines()
        .enumerate()
        .filter(|(_, line)| !line.starts_with('#'))
        .map(|(index, line)| {
            let fields: Vec<&str> = line.split(' ').collect();
            Case {
                line: index + 1,
                valid: fields[0] == "1",
                public_key: unhex(fields[1]),
                signature: unhex(fields[2]),
                message: unhex(fields[3]),
                context: unhex(fields[4]),
            }
        })
        .collect()
}

fn ml_dsa_65_accepts(case: &Case) -> bool {
    let Ok(key) = <[u8; ml_dsa_65::PK_LEN]>::try_from(case.public_key.as_slice()) else {
        return false;
    };
    let Ok(signature) = <[u8; ml_dsa_65::SIG_LEN]>::try_from(case.signature.as_slice()) else {
        return false;
    };
    ml_dsa_65::PublicKey::try_from_bytes(key)
        .is_ok_and(|key| key.verify(&case.message, &signature, &case.context))
}

fn check(file: &str, name: &str, accepts: impl Fn(&Case) -> bool) {
    let all = cases(file);
    assert!(!all.is_empty());
    assert!(all.iter().any(|c| c.valid), "{name}: no valid cases");
    assert!(all.iter().any(|c| !c.valid), "{name}: no invalid cases");
    for case in &all {
        assert_eq!(accepts(case), case.valid, "{name}, line {}", case.line);
    }
}

#[test]
fn ml_dsa_65_matches_nist_acvp() {
    check(
        include_str!("vectors/ml-dsa-65-verify-acvp.txt"),
        "ACVP ML-DSA-65",
        ml_dsa_65_accepts,
    );
}

#[test]
fn ml_dsa_65_matches_wycheproof() {
    check(
        include_str!("vectors/ml-dsa-65-verify-wycheproof.txt"),
        "Wycheproof ML-DSA-65",
        ml_dsa_65_accepts,
    );
}

#[test]
fn slh_dsa_sha2_192s_matches_nist_acvp() {
    check(
        include_str!("vectors/slh-dsa-sha2-192s-verify-acvp.txt"),
        "ACVP SLH-DSA-SHA2-192s",
        |case| {
            let Ok(key) = <[u8; slh_dsa_sha2_192s::PK_LEN]>::try_from(case.public_key.as_slice())
            else {
                return false;
            };
            let Ok(signature) =
                <[u8; slh_dsa_sha2_192s::SIG_LEN]>::try_from(case.signature.as_slice())
            else {
                return false;
            };
            slh_dsa_sha2_192s::PublicKey::try_from_bytes(key)
                .is_ok_and(|key| key.verify(&case.message, &signature, &case.context))
        },
    );
}
