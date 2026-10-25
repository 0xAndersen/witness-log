//! `witness-log witness-network ...`: describe a witness-log log to
//! witnesses that have not enrolled it, in the formats the public witness
//! network (witness-network.org) uses.
//!
//! Witnesses outside this project admit logs one origin at a time. The
//! witness network gathers those admissions into shared log lists
//! (`logs/v0`, <https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md>)
//! that participating witnesses poll and configure automatically: the
//! transparency-dev `omniwitness`, for one, with
//! `--public_witness_config_url`. A log asks to be added by email.
//!
//! * `log-list` prints a `logs/v0` list naming the given logs: what to
//!   serve to your own omniwitness (or any witness that reads log lists),
//!   and the entry the witness network's maintainers add for you.
//! * `request` prints the participation request: origin line, vkey,
//!   add-checkpoint rate, log list and contact, as the network's
//!   guidelines ask, with the `logs/v0` entries attached.
//!
//! Nothing is sent: the operator reads it and sends it.
//!
//! A log is named by its fleet state directory (`--fleet`, RFC-0001: one
//! log per organisation, the unit a witness should admit), an agent's
//! identity (`--identity`: the agent's own log, whose origin is
//! `witness-log/<hex>`), or any C2SP log vkey (`--vkey`).

use crate::fleet_cmd::fleet_public;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use witness_log_core::c2sp::{
    canonical_origin, identity_from_canonical_origin, VerifierKey, SIG_TYPE_COSIGNATURE_V1,
    SIG_TYPE_ED25519,
};

const USAGE: &str = "usage:
  witness-log witness-network log-list <logs> (--every SECS | --qpd N) --contact TEXT
  witness-log witness-network request  <logs> (--every SECS | --qpd N) --contact TEXT
                                       [--list testing|staging] [--about TEXT]
    <logs> is one or more of (each repeatable):
      --fleet <dir>       a fleet log (RFC-0001), from its fleet.json
      --identity <hex>    an agent's own log, origin witness-log/<hex>
      --vkey <log vkey>   any C2SP checkpoint log whose origin is its key name
                          (Ed25519, key type 0x01)
    --every SECS   how often the log asks each witness to cosign (as given to
                   `fleet serve --witness-every`); qpd = ceil(86400 / SECS)
    --qpd N        add-checkpoint requests per day, 1 <= N < 2^31, instead
    --contact      how witness operators reach you (one line)
  `log-list` prints a logs/v0 log list (what omniwitness's
  --public_witness_config_url reads); `request` prints the participation
  request for the public witness network (witness-network.org), to send to
  participate (at) lists.witness-network.org. Nothing is sent from here.";

/// The participation address, spelled as witness-network.org spells it.
pub(crate) const PARTICIPATE: &str = "participate (at) lists.witness-network.org";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(crate::exit::USAGE)
}

/// One log to describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedLog {
    pub origin: String,
    pub vkey: String,
    pub what: String,
}

pub fn run(args: &[String]) -> ExitCode {
    let sub = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);
    if crate::asks_sub_help(sub, rest) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let request = match sub {
        Some("log-list") => false,
        Some("request") => true,
        _ => return usage_err("witness-network: expected log-list or request"),
    };
    let name = if request { "request" } else { "log-list" };
    let mut valued = vec![
        "--fleet",
        "--identity",
        "--vkey",
        "--every",
        "--qpd",
        "--contact",
    ];
    if request {
        valued.extend(["--list", "--about"]);
    }
    if let Err(e) = check_flags(rest, &valued) {
        return usage_err(&format!("witness-network {name}: {e}"));
    }
    let logs = match collect_logs(rest) {
        Ok(l) => l,
        Err(Problem::Usage(e)) => return usage_err(&format!("witness-network {name}: {e}")),
        Err(Problem::Input(e)) => {
            eprintln!("witness-network {name}: {e}");
            return ExitCode::from(crate::exit::USAGE);
        }
    };
    let (qpd, every) = match rate(rest) {
        Ok(r) => r,
        Err(e) => return usage_err(&format!("witness-network {name}: {e}")),
    };
    let contact = match crate::flag_value(rest, "--contact").map(|c| one_line(&c, "--contact")) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return usage_err(&format!("witness-network {name}: {e}")),
        None => {
            return usage_err(&format!(
                "witness-network {name}: --contact is required: how witness operators reach you \
                 if your log misbehaves (an address or an about page)"
            ))
        }
    };
    let list_text = log_list(&logs, qpd, &contact);
    if !request {
        print!("{list_text}");
        return ExitCode::SUCCESS;
    }
    let list = crate::flag_value(rest, "--list").unwrap_or_else(|| "testing".into());
    if !matches!(list.as_str(), "testing" | "staging") {
        return usage_err(&format!(
            "witness-network request: --list must be testing or staging (production is not \
             open yet), not {list:?}"
        ));
    }
    let about = match crate::flag_value(rest, "--about").map(|a| one_line(&a, "--about")) {
        Some(Ok(a)) => Some(a),
        Some(Err(e)) => return usage_err(&format!("witness-network request: {e}")),
        None => None,
    };
    print!(
        "{}",
        request_text(
            &logs,
            qpd,
            every,
            &contact,
            &list,
            about.as_deref(),
            &list_text
        )
    );
    eprintln!(
        "Send the text above to {PARTICIPATE} (nothing was sent). Once a list carries your \
         log, add each witness that configures that list to your directory, from the vkey \
         and add-checkpoint URL on its about page:\n  witness-log directory add trusted.json \
         --vkey <its vkey> --org \"<its operator>\" --url <its add-checkpoint URL>\nSee \
         https://github.com/0xAndersen/witness-log/blob/main/docs/wiki/Public-Witness-Network.md"
    );
    ExitCode::SUCCESS
}

/// Every argument is a known flag followed by a value.
fn check_flags(args: &[String], valued: &[&str]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if !valued.contains(&a) {
            return Err(format!("unexpected argument {a:?}"));
        }
        match args.get(i + 1) {
            Some(v) if !v.starts_with("--") => i += 2,
            _ => return Err(format!("{a} requires a value")),
        }
    }
    Ok(())
}

enum Problem {
    Usage(String),
    Input(String),
}

/// The logs named by `--fleet`, `--identity` and `--vkey`, in the order
/// given. Each must be a C2SP checkpoint log with an Ed25519 key (type
/// 0x01) named as its origin; an origin may appear once.
fn collect_logs(args: &[String]) -> Result<Vec<ListedLog>, Problem> {
    let mut logs = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        let (flag, value) = (args[i].as_str(), args[i + 1].as_str());
        i += 2;
        let log = match flag {
            "--fleet" => {
                let (origin, org, vk) = fleet_public(Path::new(value)).map_err(Problem::Input)?;
                if !valid_origin(&origin) {
                    // A no-break space, say: note.NewVerifier refuses the
                    // key name, and omniwitness then refuses the whole list.
                    return Err(Problem::Input(format!(
                        "{value}: the fleet origin {} has whitespace, which a vkey name and a log list cannot carry",
                        witness_log_core::echo::quoted(&origin)
                    )));
                }
                ListedLog {
                    origin,
                    vkey: vk.encode(),
                    what: format!(
                        "a witness-log fleet log (RFC-0001) run by {org}: one append-only log \
                         whose entries are the signed checkpoints of that organisation's AI agents"
                    ),
                }
            }
            "--identity" => {
                let origin = format!("witness-log/{}", value.trim());
                let vk = identity_from_canonical_origin(&origin).ok_or_else(|| {
                    Problem::Usage(format!(
                        "--identity must be an agent's Ed25519 public key, 64 lowercase hex \
                         characters as `log info` prints it; {} is not",
                        witness_log_core::echo::quoted(value)
                    ))
                })?;
                ListedLog {
                    origin: canonical_origin(&vk),
                    vkey: VerifierKey::for_ed25519(&canonical_origin(&vk), &vk).encode(),
                    what: "one AI agent's own witness-log: an RFC 6962 Merkle log of its \
                           actions, whose origin is witness-log/ followed by its Ed25519 public \
                           key in hex, so it cannot collide with another log"
                        .into(),
                }
            }
            "--vkey" => log_from_vkey(value).map_err(Problem::Usage)?,
            _ => continue,
        };
        logs.push(log);
    }
    if logs.is_empty() {
        return Err(Problem::Usage(
            "name at least one log: --fleet <dir>, --identity <hex> or --vkey <log vkey>".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for l in &logs {
        if !seen.insert(l.origin.as_str()) {
            return Err(Problem::Usage(format!(
                "the log {} is named twice",
                witness_log_core::echo::quoted(&l.origin)
            )));
        }
    }
    Ok(logs)
}

fn log_from_vkey(value: &str) -> Result<ListedLog, String> {
    let vk = VerifierKey::parse(value.trim()).map_err(|e| format!("--vkey: bad vkey: {e}"))?;
    if vk.sig_type == SIG_TYPE_COSIGNATURE_V1 {
        return Err(
            "--vkey: this is a witness's cosignature key (type 0x04); a log list names a \
             log's checkpoint signing key (Ed25519, type 0x01)"
                .into(),
        );
    }
    if vk.sig_type != SIG_TYPE_ED25519 || vk.public_key.len() != 32 {
        return Err(format!(
            "--vkey: key type 0x{:02x} is not Ed25519 (0x01), the log key type witness-log \
             signs with",
            vk.sig_type
        ));
    }
    if !valid_origin(&vk.name) {
        return Err("--vkey: the key name is not a usable origin line".into());
    }
    let what = if vk.name.starts_with("witness-log/") {
        // An agent origin names its key: any other key under it would never
        // verify at a witness-log witness, and is not a witness-log log.
        let named = identity_from_canonical_origin(&vk.name).ok_or_else(|| {
            "--vkey: witness-log/ origins are witness-log/<64 lowercase hex>".to_string()
        })?;
        if named.to_bytes().as_slice() != vk.public_key.as_slice() {
            return Err("--vkey: the origin names a different key than the vkey carries".into());
        }
        "one AI agent's own witness-log, whose origin names its Ed25519 public key".to_string()
    } else {
        "a C2SP checkpoint log".to_string()
    };
    Ok(ListedLog {
        origin: vk.name.clone(),
        vkey: vk.encode(),
        what,
    })
}

/// A C2SP origin line: non-empty, at most 255 bytes, no space and no
/// control character (it is one whitespace-separated field of a log list).
fn valid_origin(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// One line of text for a log list or request: trimmed, inner whitespace
/// runs collapsed, no control characters, at most 300 bytes.
fn one_line(s: &str, flag: &str) -> Result<String, String> {
    if s.chars().any(|c| c.is_control() && c != '\t') {
        return Err(format!("{flag} must be one line of text"));
    }
    let t = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.is_empty() {
        return Err(format!("{flag} is empty"));
    }
    if t.len() > 300 {
        return Err(format!("{flag} is longer than 300 bytes"));
    }
    Ok(t)
}

/// The largest qpd the log-list format allows, exclusive: 2^31.
const QPD_LIMIT: u64 = 1 << 31;

/// `(qpd, every)` from `--qpd N` or `--every SECS`.
fn rate(args: &[String]) -> Result<(u64, Option<u64>), String> {
    let qpd = crate::flag_value(args, "--qpd");
    let every = crate::flag_value(args, "--every");
    match (qpd, every) {
        (Some(_), Some(_)) => Err("give --every or --qpd, not both".into()),
        (None, None) => Err(
            "say how often the log will ask witnesses to cosign: --every SECS (what you pass \
             to `fleet serve --witness-every`) or --qpd N (requests per day). Witnesses may \
             rate-limit or drop a log that exceeds what it declared"
                .into(),
        ),
        (Some(q), None) => match witness_log_core::c2sp::parse_canonical_u64(&q) {
            Some(n) if (1..QPD_LIMIT).contains(&n) => Ok((n, None)),
            _ => Err(format!(
                "--qpd must be a whole number from 1 to 2147483647, written without leading \
                 zeros, not {q:?}"
            )),
        },
        (None, Some(s)) => match witness_log_core::c2sp::parse_canonical_u64(&s) {
            Some(n) if n >= 1 => Ok((qpd_for_every(n), Some(n))),
            _ => Err(format!(
                "--every must be a whole number of seconds, at least 1, not {s:?}"
            )),
        },
    }
}

/// Requests per day for one request every `secs` seconds, rounded up.
pub(crate) fn qpd_for_every(secs: u64) -> u64 {
    86_400u64.div_ceil(secs.max(1))
}

fn every_phrase(secs: u64) -> String {
    let unit = |n: u64, one: &str| {
        if n == 1 {
            format!("every {one}")
        } else {
            format!("every {n} {one}s")
        }
    };
    if secs % 86_400 == 0 {
        unit(secs / 86_400, "day")
    } else if secs % 3_600 == 0 {
        unit(secs / 3_600, "hour")
    } else if secs % 60 == 0 {
        unit(secs / 60, "minute")
    } else {
        unit(secs, "second")
    }
}

/// A `logs/v0` list naming `logs`, every one with the same `qpd` and
/// `contact`.
pub(crate) fn log_list(logs: &[ListedLog], qpd: u64, contact: &str) -> String {
    let mut s = format!(
        "# A log list (logs/v0, https://witness-network.org/log-list-format)\n\
         # written by witness-log {}\n\
         logs/v0\n",
        env!("CARGO_PKG_VERSION")
    );
    for l in logs {
        // The key name is the origin, so no `origin` line (the format's
        // recommendation for new logs).
        let _ = write!(s, "\nvkey {}\nqpd {qpd}\ncontact {contact}\n", l.vkey);
    }
    s
}

fn request_text(
    logs: &[ListedLog],
    qpd: u64,
    every: Option<u64>,
    contact: &str,
    list: &str,
    about: Option<&str>,
    list_text: &str,
) -> String {
    let subject = match logs {
        [one] => format!("Log participation request: {}", one.origin),
        [first, rest @ ..] => format!(
            "Log participation request: {} and {} more",
            first.origin,
            rest.len()
        ),
        [] => "Log participation request".into(),
    };
    let rate = match every {
        Some(secs) => format!(
            "at most {qpd} add-checkpoint requests per day ({} per witness)",
            every_phrase(secs)
        ),
        None => format!("at most {qpd} add-checkpoint requests per day"),
    };
    let list_note = match list {
        "staging" => "staging: a real deployment we are happy to dogfood",
        _ => "testing: development and shorter-lived testing",
    };
    let mut s = format!("To: {PARTICIPATE}\nSubject: {subject}\n\nHello,\n\n");
    let _ = writeln!(
        s,
        "We would like {} added to the {list} log list.\n",
        if logs.len() == 1 {
            "this log"
        } else {
            "these logs"
        }
    );
    for (n, l) in logs.iter().enumerate() {
        if logs.len() > 1 {
            let _ = writeln!(s, "Log {}", n + 1);
        }
        let _ = writeln!(s, "  Origin line:         {}", l.origin);
        let _ = writeln!(s, "  Public key (vkey):   {}", l.vkey);
        let _ = writeln!(
            s,
            "                       Ed25519, key type 0x01; key name = origin"
        );
        let _ = writeln!(s, "  Add-checkpoint rate: {rate}");
        let _ = writeln!(s, "  What it is:          {}\n", l.what);
    }
    let _ = writeln!(s, "Log list: {list_note}");
    let _ = writeln!(s, "Contact:  {contact}\n");
    if let Some(a) = about {
        let _ = writeln!(s, "{a}\n");
    }
    let _ = writeln!(
        s,
        "witness-log (https://github.com/0xAndersen/witness-log) makes AI agents' actions \
         tamper-evident. Its checkpoints are c2sp.org/tlog-checkpoint signed notes, submitted \
         with c2sp.org/tlog-witness add-checkpoint; verifiers check cosignature/v1 lines \
         offline against the witnesses' published vkeys.\n"
    );
    let _ = writeln!(s, "The entries, in the logs/v0 format:\n");
    for line in list_text.lines() {
        if line.is_empty() {
            s.push('\n');
        } else {
            let _ = writeln!(s, "    {line}");
        }
    }
    s.push_str("\nThank you.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(seed: u8) -> ListedLog {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        log_from_vkey(&VerifierKey::for_ed25519(&canonical_origin(&vk), &vk).encode()).unwrap()
    }

    /// The rules of transparency-dev/witness-network's `cmd/validate`
    /// (the maintainers' check on every list) and of omniwitness's parser
    /// (`config.ParsePublicWitnessConfig`), restated: a `logs/v0` header
    /// first, then per log `vkey`, optional `origin`, `qpd` in [1, 2^31)
    /// and a non-empty `contact`, in that order.
    fn validate(list: &str) -> Result<usize, String> {
        let mut header = false;
        let mut expect = "vkey";
        let mut logs = 0;
        for (n, raw) in list.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !header {
                if line != "logs/v0" {
                    return Err(format!("line {n}: no header"));
                }
                header = true;
                continue;
            }
            let (kw, rest) = line.split_once(' ').unwrap_or((line, ""));
            match kw {
                "vkey" if expect == "vkey" => {
                    let vk = VerifierKey::parse(rest).map_err(|e| e.to_string())?;
                    if vk.sig_type != SIG_TYPE_ED25519 || rest.contains(' ') {
                        return Err(format!("line {n}: bad vkey"));
                    }
                    expect = "origin";
                }
                "origin" if expect == "origin" && !rest.is_empty() => expect = "qpd",
                "qpd" if expect == "origin" || expect == "qpd" => {
                    let v: i64 = rest.parse().map_err(|_| format!("line {n}: qpd"))?;
                    if !(1..(1i64 << 31)).contains(&v) || rest.starts_with('0') {
                        return Err(format!("line {n}: qpd range"));
                    }
                    expect = "contact";
                }
                "contact" if expect == "contact" && !rest.trim().is_empty() => {
                    expect = "vkey";
                    logs += 1;
                }
                _ => return Err(format!("line {n}: unexpected {line:?} (expected {expect})")),
            }
        }
        if !header || expect != "vkey" {
            return Err("incomplete".into());
        }
        Ok(logs)
    }

    #[test]
    fn a_log_list_passes_the_networks_validator() {
        let logs = [agent(1), agent(2)];
        let text = log_list(
            &logs,
            1440,
            "ops (at) example.org | https://example.org/about",
        );
        assert_eq!(validate(&text), Ok(2), "{text}");
        assert!(text.contains(&format!("vkey {}\nqpd 1440\n", logs[0].vkey)));
    }

    #[test]
    fn the_rate_is_rounded_up_and_bounded() {
        assert_eq!(qpd_for_every(1), 86_400);
        assert_eq!(qpd_for_every(60), 1_440);
        assert_eq!(qpd_for_every(7), 12_343);
        assert_eq!(qpd_for_every(86_400 * 3), 1);
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(rate(&a(&["--every", "300"])), Ok((288, Some(300))));
        assert_eq!(rate(&a(&["--qpd", "24"])), Ok((24, None)));
        for bad in [
            &["--qpd", "0"][..],
            &["--qpd", "024"],
            &["--qpd", "2147483648"],
            &["--every", "0"],
            &["--every", "-5"],
            &["--qpd", "1", "--every", "1"],
            &[],
        ] {
            assert!(rate(&a(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_log_keys_named_as_their_origin_are_listed() {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();
        let ok = VerifierKey::for_ed25519("example.org/log", &vk).encode();
        assert_eq!(log_from_vkey(&ok).unwrap().origin, "example.org/log");
        // A witness key, not a log key.
        let mut cos = VerifierKey::for_ed25519("w.example.org", &vk);
        cos.sig_type = SIG_TYPE_COSIGNATURE_V1;
        assert!(log_from_vkey(&cos.encode()).unwrap_err().contains("0x04"));
        // An agent origin that names another key.
        let liar = VerifierKey::for_ed25519(&canonical_origin(&other), &vk).encode();
        assert!(log_from_vkey(&liar).unwrap_err().contains("different key"));
        assert!(log_from_vkey("not a vkey").is_err());
    }

    #[test]
    fn contact_and_about_are_one_line() {
        assert_eq!(one_line("  a   b ", "--contact").unwrap(), "a b");
        assert!(one_line("a\nb", "--contact").is_err());
        assert!(one_line("   ", "--contact").is_err());
        assert!(one_line(&"x".repeat(301), "--contact").is_err());
    }

    #[test]
    fn the_request_names_every_field_the_guidelines_ask_for() {
        let logs = [agent(3)];
        let list = log_list(&logs, 288, "ops (at) example.org");
        let r = request_text(
            &logs,
            288,
            Some(300),
            "ops (at) example.org",
            "testing",
            None,
            &list,
        );
        for want in [
            "To: participate (at) lists.witness-network.org",
            &format!("Subject: Log participation request: {}", logs[0].origin),
            &format!("Origin line:         {}", logs[0].origin),
            &format!("Public key (vkey):   {}", logs[0].vkey),
            "at most 288 add-checkpoint requests per day (every 5 minutes per witness)",
            "Log list: testing",
            "Contact:  ops (at) example.org",
            &format!("    vkey {}", logs[0].vkey),
        ] {
            assert!(r.contains(want), "missing {want:?} in\n{r}");
        }
        assert_eq!(every_phrase(3_600), "every hour");
        assert_eq!(every_phrase(90), "every 90 seconds");
        assert_eq!(every_phrase(172_800), "every 2 days");
    }
}
