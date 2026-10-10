//! `witness-log explain` — verdict and check semantics as a command
//! rather than only as prose in a document.
//!
//! This exists for two audiences. A human who just got an unexpected
//! verdict shouldn't have to find the right section of THREAT_MODEL.md to
//! learn what it means. And an agent that hits an unexpected verdict
//! mid-workflow can call `explain --json` to get the same answer
//! programmatically, without a human in the loop and without fetching
//! documentation it has no way to parse.
//!
//! Everything here is a restatement of SPEC.md §9.2 and THREAT_MODEL.md.
//! If they ever disagree, those documents are normative and this is the bug.

use std::process::ExitCode;

struct VerdictDoc {
    name: &'static str,
    exit_code: u8,
    summary: &'static str,
    proves: &'static [&'static str],
    does_not_prove: &'static [&'static str],
    next_step: &'static str,
}

const VERDICTS: &[VerdictDoc] = &[
    VerdictDoc {
        name: "WITNESSED",
        exit_code: 0,
        summary: "Strongest verdict. Cryptography, identity, and structure all check out, AND independent witnesses from a directory YOU supplied corroborate this checkpoint.",
        proves: &[
            "the leaves reproduce the signed checkpoint root exactly",
            "the checkpoint was signed by the identity you pinned with --identity",
            "at least one witness that is NOT project-operated countersigned it",
            "operator diversity across counted receipts is at least 50%",
            "the receipt count met your --threshold",
        ],
        does_not_prove: &[
            "that the logged content is TRUE — an agent can honestly log a false statement",
            "that the host wasn't compromised before the signature was made",
            "anything stronger than your trusted directory actually is; if every witness in it is secretly one operator, this verdict inherits that weakness",
        ],
        next_step: "Nothing further. This is the ceiling. Read THREAT_MODEL.md for what it still doesn't cover.",
    },
    VerdictDoc {
        name: "CONSISTENT-UNWITNESSED",
        exit_code: 10,
        summary: "Cryptography, identity, and structure all check out. You supplied a trusted directory, but witness coverage is absent, below your threshold, or entirely project-operated.",
        proves: &[
            "the leaves reproduce the signed checkpoint root exactly",
            "the checkpoint was signed by the identity you pinned",
            "nothing was rewritten after signing",
        ],
        does_not_prove: &[
            "equivocation resistance — a log with no independent witnesses can show one history to you and a different one to someone else, and neither of you can tell",
            "that the checkpoint's own timestamp is accurate; it's self-asserted",
        ],
        next_step: "Get more independent witnesses into your trusted directory, lower --threshold if your risk tolerance genuinely allows it, or treat this as the honest ceiling for a log that isn't witnessed yet.",
    },
    VerdictDoc {
        name: "UNANCHORED",
        exit_code: 20,
        summary: "Every check passed, but you supplied NO external trust anchor — so this proves the file doesn't contradict itself, and nothing more.",
        proves: &[
            "the dossier is internally consistent: leaves reproduce the root, signatures verify against the keys the dossier itself carries",
        ],
        does_not_prove: &[
            "that this dossier is about the party you think it is",
            "ANYTHING about authenticity to someone who doesn't already trust the author",
            "that the witnesses it lists are real, independent, or exist at all — a fabricated dossier ships its own witness directory and reaches exactly this verdict",
        ],
        next_step: "Re-run with --identity <hex> (the identity you expected, from somewhere the dossier's author doesn't control) and --directory <path> (a witness directory you trust). Both are required to exceed this verdict; that requirement is the point, not an inconvenience.",
    },
    VerdictDoc {
        name: "DIVERGED",
        exit_code: 30,
        summary: "A check FAILED. Something about this dossier does not hold together.",
        proves: &[
            "one of: a signature is invalid, the leaves do not reproduce the signed root, the claimed identity does not match the signing key, a leaf is structurally malformed, or a key binding is invalid or expired",
        ],
        does_not_prove: &[
            "necessarily that someone acted maliciously — a truncated file or a mismatched --identity produces this too. The verdict says a check failed, not why someone caused it to fail.",
        ],
        next_step: "Read the individual check lines above the verdict: exactly one of them will show which failed. If 'Identity bound' failed, confirm the --identity you passed is the one you actually expected.",
    },
];

pub fn run_explain(topic: Option<&str>, json: bool) -> ExitCode {
    let selected: Vec<&VerdictDoc> = match topic {
        None | Some("verdict") | Some("verdicts") => VERDICTS.iter().collect(),
        Some(t) => {
            let needle = t.to_ascii_uppercase().replace(['_', ' '], "-");
            let found: Vec<&VerdictDoc> = VERDICTS.iter().filter(|v| v.name == needle).collect();
            if found.is_empty() {
                eprintln!("unknown topic: {t}");
                eprintln!("  known: witnessed, consistent-unwitnessed, unanchored, diverged");
                eprintln!("  or run `witness-log explain` for all of them");
                return ExitCode::from(2);
            }
            found
        }
    };

    if json {
        let out: Vec<serde_json::Value> = selected
            .iter()
            .map(|v| {
                serde_json::json!({
                    "verdict": v.name,
                    "exit_code": v.exit_code,
                    "summary": v.summary,
                    "proves": v.proves,
                    "does_not_prove": v.does_not_prove,
                    "next_step": v.next_step,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return ExitCode::SUCCESS;
    }

    for v in selected {
        println!();
        println!("  {}  (exit code {})", v.name, v.exit_code);
        println!("  {}", "─".repeat(66));
        println!();
        for line in wrap(v.summary, 68) {
            println!("  {line}");
        }
        println!();
        println!("  What it proves:");
        for p in v.proves {
            for (i, line) in wrap(p, 64).into_iter().enumerate() {
                println!("    {} {line}", if i == 0 { "·" } else { " " });
            }
        }
        println!();
        println!("  What it does NOT prove:");
        for p in v.does_not_prove {
            for (i, line) in wrap(p, 64).into_iter().enumerate() {
                println!("    {} {line}", if i == 0 { "·" } else { " " });
            }
        }
        println!();
        println!("  Next step:");
        for line in wrap(v.next_step, 66) {
            println!("    {line}");
        }
        println!();
    }
    ExitCode::SUCCESS
}

/// Minimal greedy word wrap. Deliberately dependency-free — pulling in a
/// text-layout crate to format help output would be a poor trade for a
/// security library that otherwise has a very small dependency surface.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
