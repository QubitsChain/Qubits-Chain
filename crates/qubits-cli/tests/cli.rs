use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PASSWORD: &str = "a long enough password";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::write(env.path("pw"), format!("{PASSWORD}\n")).unwrap();
        fs::write(env.path("wrong-pw"), "not the right password\n").unwrap();
        fs::write(env.path("short-pw"), "short\n").unwrap();
        fs::write(env.path("msg"), b"I own this key").unwrap();
        fs::write(env.path("other-msg"), b"I own a different key").unwrap();
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn qubits(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_qubits"))
            .current_dir(self.dir.path())
            .args(args)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.qubits(args);
        assert!(
            out.status.success(),
            "`qubits {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn err(&self, args: &[&str]) -> String {
        let out = self.qubits(args);
        assert!(
            !out.status.success(),
            "`qubits {}` unexpectedly succeeded",
            args.join(" ")
        );
        String::from_utf8(out.stderr).unwrap()
    }
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .unwrap_or_else(|| panic!("no `{name}` in output: {output}"))
        .trim()
}

#[test]
fn new_key_sign_and_verify_for_each_scheme() {
    for scheme in ["ml-dsa-65", "slh-dsa-sha2-192s"] {
        let env = Env::new();
        let created = env.ok(&[
            "key",
            "new",
            "--out",
            "k.json",
            "--scheme",
            scheme,
            "--password-file",
            "pw",
        ]);
        assert_eq!(field(&created, "scheme"), scheme);
        let pk = field(&created, "public key").to_owned();

        let shown = env.ok(&["key", "show", "--key", "k.json"]);
        assert_eq!(field(&shown, "public key"), pk);

        let sig = env.ok(&[
            "sign",
            "--key",
            "k.json",
            "--message",
            "msg",
            "--password-file",
            "pw",
        ]);
        fs::write(env.path("sig"), sig.trim()).unwrap();

        let verified = env.ok(&[
            "verify",
            "--public-key",
            &pk,
            "--signature",
            "@sig",
            "--message",
            "msg",
        ]);
        assert!(verified.starts_with("OK"), "{verified}");

        let stderr = env.err(&[
            "verify",
            "--public-key",
            &pk,
            "--signature",
            "@sig",
            "--message",
            "other-msg",
        ]);
        assert!(stderr.contains("invalid signature"), "{stderr}");
    }
}

#[test]
fn key_file_is_private_and_never_overwritten() {
    let env = Env::new();
    env.ok(&["key", "new", "--out", "k.json", "--password-file", "pw"]);
    let original = fs::read(env.path("k.json")).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(env.path("k.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let stderr = env.err(&["key", "new", "--out", "k.json", "--password-file", "pw"]);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(fs::read(env.path("k.json")).unwrap(), original);
}

#[test]
fn wrong_password_cannot_sign() {
    let env = Env::new();
    env.ok(&["key", "new", "--out", "k.json", "--password-file", "pw"]);
    let stderr = env.err(&[
        "sign",
        "--key",
        "k.json",
        "--message",
        "msg",
        "--password-file",
        "wrong-pw",
    ]);
    assert!(stderr.contains("wrong password"), "{stderr}");
}

#[test]
fn short_password_is_refused() {
    let env = Env::new();
    let stderr = env.err(&[
        "key",
        "new",
        "--out",
        "k.json",
        "--password-file",
        "short-pw",
    ]);
    assert!(stderr.contains("at least 12 characters"), "{stderr}");
    assert!(!Path::new(&env.path("k.json")).exists());
}

#[test]
fn signature_from_another_key_is_rejected() {
    let env = Env::new();
    let a = env.ok(&["key", "new", "--out", "a.json", "--password-file", "pw"]);
    env.ok(&["key", "new", "--out", "b.json", "--password-file", "pw"]);
    let sig = env.ok(&[
        "sign",
        "--key",
        "b.json",
        "--message",
        "msg",
        "--password-file",
        "pw",
    ]);
    let stderr = env.err(&[
        "verify",
        "--public-key",
        field(&a, "public key"),
        "--signature",
        sig.trim(),
        "--message",
        "msg",
    ]);
    assert!(stderr.contains("invalid signature"), "{stderr}");
}

#[test]
fn malformed_inputs_give_clear_errors() {
    let env = Env::new();
    let stderr = env.err(&["key", "new", "--out", "k.json", "--scheme", "ed25519"]);
    assert!(stderr.contains("unknown signature scheme"), "{stderr}");

    let stderr = env.err(&[
        "verify",
        "--public-key",
        "zz",
        "--signature",
        "00",
        "--message",
        "msg",
    ]);
    assert!(stderr.contains("not valid hex"), "{stderr}");

    let stderr = env.err(&[
        "verify",
        "--public-key",
        "01ab",
        "--signature",
        "01ab",
        "--message",
        "msg",
    ]);
    assert!(stderr.contains("invalid public key length"), "{stderr}");

    let stderr = env.err(&["key", "show", "--key", "missing.json"]);
    assert!(stderr.contains("missing.json"), "{stderr}");
}
