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
        summary: "Strongest verdict. Cryptography and structure check out, AND witnesses run by at least two distinct independent operators, from a directory YOU supplied, cosigned this checkpoint. By default (strict) `verify` exits 0 only when the cosigners are also a strict majority of your directory; with fewer it still says WITNESSED but exits 11 (see SPLIT-VIEW).",
        proves: &[
            "the leaves reproduce the signed checkpoint root exactly",
            "if you passed --identity: the checkpoint was signed by that identity. Without --identity the verdict says nothing about whose log this is (the output warns)",
            "valid receipts from witnesses in YOUR trusted directory come from at least two distinct independent operators (project-operated witnesses count as one bucket; witnesses run by the log's own operator count as none)",
            "the receipt count met your --threshold as a fraction of that directory (or your --min-witnesses)",
            "with exit 0 under strict: the cosigners are a strict majority of your directory, so no conflicting history can have been cosigned by a different majority",
        ],
        does_not_prove: &[
            "that the logged content is TRUE — an agent can honestly log a false statement",
            "that the host wasn't compromised before the signature was made",
            "anything stronger than your trusted directory actually is; if every witness in it is secretly one operator, this verdict inherits that weakness",
        ],
        next_step: "Nothing further. This is the ceiling. Read THREAT_MODEL.md for what it still doesn't cover.",
    },
    VerdictDoc {
        name: "SPLIT-VIEW",
        exit_code: 11,
        summary: "Not a separate verdict: the report still says WITNESSED. Exit 11 means the cosigners are fewer than a strict majority of the directory you supplied, so the rest of that directory could have cosigned a conflicting history and neither set of witnesses would know. Strict is the default since 0.5.0.",
        proves: &[
            "everything WITNESSED proves",
        ],
        does_not_prove: &[
            "that no other history for this identity was cosigned by witnesses in your directory that did not cosign this one",
        ],
        next_step: "Verify against the directory the log actually submitted to (a curated subset, not a whole registry), have the log submit to more of your directory (`witness-log submit` asks a majority by default), or accept the weaker guarantee explicitly with --allow-sub-majority (exit 0, warning printed). --no-strict restores the 0.4 behaviour for one release.",
    },
    VerdictDoc {
        name: "CONSISTENT-UNWITNESSED",
        exit_code: 10,
        summary: "Cryptography and structure check out. You supplied a trusted directory, but the receipts fall short of WITNESSED: none are from your directory, the count is below your threshold, or fewer than two distinct independent operators cosigned (the verdict line names which).",
        proves: &[
            "the leaves reproduce the signed checkpoint root exactly",
            "if you passed --identity: the checkpoint was signed by that identity",
            "nothing was rewritten after signing",
        ],
        does_not_prove: &[
            "equivocation resistance — a log with no independent witnesses can show one history to you and a different one to someone else, and neither of you can tell",
            "that the checkpoint's own timestamp is accurate; it's self-asserted",
        ],
        next_step: "Have the log submit its checkpoint to witnesses run by at least two distinct operators that are in your trusted directory (`witness-log submit`), lower --threshold if your risk tolerance allows it, or treat this as the honest ceiling for a log that isn't witnessed yet.",
    },
    VerdictDoc {
        name: "UNANCHORED",
        exit_code: 20,
        summary: "Every check passed, but you supplied no --directory, so the receipts could not be scored against anything you trust. This proves the file doesn't contradict itself, and nothing more.",
        proves: &[
            "the dossier is internally consistent: leaves reproduce the root, signatures verify against the keys the dossier itself carries",
        ],
        does_not_prove: &[
            "that this dossier is about the party you think it is",
            "ANYTHING about authenticity to someone who doesn't already trust the author",
            "that the witnesses it lists are real, independent, or exist at all — a fabricated dossier ships its own witness directory and reaches exactly this verdict",
        ],
        next_step: "Re-run with --directory <path> (a witness directory you trust): that is what lifts the ceiling. Pass --identity <hex> as well (the identity you expected, from somewhere the dossier's author doesn't control) so the verdict is about a specific party and not just about some log. A gate should always pass both.",
    },
    VerdictDoc {
        name: "DIVERGED",
        exit_code: 30,
        summary: "The dossier is valid on its own, and it contradicts evidence you supplied about the same identity: a head you already trusted (--known-head) that its leaves do not reproduce, or a witness's equivocation proof (--evidence). The identity has shown two different histories. One file on its own is never DIVERGED (since 0.5.0; before that a failed check was reported as DIVERGED, which is now INVALID).",
        proves: &[
            "the identity signed two different histories: the one in this dossier and the one your known head or evidence file commits to",
            "the contradiction is cryptographic: both sides verify under the identity's key",
        ],
        does_not_prove: &[
            "which history is the 'true' one — that is precisely the finding",
            "malice: two journals run from one identity seed (a seed deployed twice) produce the same signal; the key names the log, so either way the identity is no longer trustworthy as one log",
        ],
        next_step: "Treat the identity as compromised or misoperated. `witness-log diff a.json b.json` shows where the histories part; the witness evidence files are portable proof for anyone you need to show.",
    },
    VerdictDoc {
        name: "INVALID",
        exit_code: 40,
        summary: "A check FAILED. The file is not valid evidence about the identity: it establishes nothing (since 0.5.0; reported as DIVERGED/30 before).",
        proves: &[
            "one of: a signature is invalid, the leaves do not reproduce the signed root, the claimed identity does not match the signing key (or the --identity you pinned), a leaf is structurally malformed, or a key binding or revocation fails",
        ],
        does_not_prove: &[
            "necessarily that someone acted maliciously — a truncated file or a mismatched --identity produces this too. The verdict says a check failed, not why",
            "anything about the identity's real history: an invalid file cannot show equivocation",
        ],
        next_step: "Read the ✗ lines under the verdict (the same text is in `--json` as report.failures). If the identity check failed, confirm the --identity you passed is the one you actually expected.",
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
                eprintln!("  known: witnessed, split-view, consistent-unwitnessed, unanchored, diverged, invalid");
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
