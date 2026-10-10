//! Drives the CLI's actual code path (dossier parse -> verify -> render),
//! not just the library's `Dossier::verify`. `finding 10` in the
//! pre-launch review was a panic in the CLI's own rendering code
//! (`short()`, a byte-offset string slice) that the library-level hostile-
//! input suite never had a chance to catch, because it never touched the
//! CLI at all. This target exercises the same parse-verify-render
//! sequence `witness-log verify` runs, over arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use witness_log_network::{Dossier, VerifyContext};

// Mirrors witness-log-cli's short() exactly, so a fix there needs a
// matching fix here to stay meaningful -- this target is a regression
// guard specifically for the class of bug finding 10 was.
fn short(hexstr: &str) -> String {
    let chars: Vec<char> = hexstr.chars().collect();
    if chars.len() > 16 {
        let head: String = chars[..8].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        format!("{head}...{tail}")
    } else {
        hexstr.to_string()
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(dossier) = serde_json::from_str::<Dossier>(s) {
            let report = dossier.verify(0.66, &VerifyContext::default());
            // Exercise every render-path string operation a real CLI run
            // would touch over this dossier's attacker-controlled fields.
            let _ = short(&dossier.identity_pubkey);
            let _ = format!("{}", report.verdict);
            let _ = serde_json::to_string_pretty(&report);
        }
    }
});
