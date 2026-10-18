//! `witness-log directory ...` -- build and edit the trusted directory file
//! that `verify`, `submit` and `journal serve` take.
//!
//! The directory a verifier trusts is the whole anchor of a WITNESSED
//! verdict, so it is a plain file the verifier assembles and keeps, never
//! something read from the dossier under test. These commands assemble
//! it from the registry's one-file-per-witness layout
//! (`registry/witnesses/*.json`, the schema `registry/build_directory.py`
//! reads) or from a C2SP verifier key an operator published.

use std::path::Path;
use std::process::ExitCode;
use witness_log_core::c2sp::{VerifierKey, SIG_TYPE_COSIGNATURE_V1};
use witness_log_network::{WitnessDirectory, WitnessEntry};

const USAGE: &str = "usage:
  witness-log directory build [--registry DIR | --url URL] [--include-project] [--allow-insecure] --out trusted.json
      Collect DIR/*.json (one directory entry per file, as `witness init` prints
      them; default DIR is ./registry/witnesses) or a directory document fetched
      from an https:// URL into {\"witnesses\": [...]}. Project-operated entries
      are left out unless --include-project. Every entry must pass the offline
      checks of registry/validate.py (known fields, 64 lowercase hex key, a real
      operator_org, runtime human or agent, an https:// URL that is not loopback,
      a C2SP key name, no duplicate key or name) or nothing is written.
      --allow-insecure accepts http:// and loopback URLs, for local tests.
  witness-log directory add <trusted.json> --vkey <c2sp vkey> --org ORG --url URL
                                           [--compute PROVIDER] [--project-operated]
      Add one witness by its C2SP cosignature verifier key (printed by `witness
      init` and served at GET /). Creates the file if it does not exist; refuses a
      key that is already listed.";

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("{msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

fn check_flags(
    args: &[String],
    value_flags: &[&str],
    bool_flags: &[&str],
) -> Result<Vec<String>, String> {
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if value_flags.contains(&a) {
            if args.get(i + 1).is_none() {
                return Err(format!("{a} requires a value"));
            }
            i += 2;
        } else if bool_flags.contains(&a) {
            i += 1;
        } else if a.starts_with("--") {
            return Err(format!("unrecognized flag: {a}"));
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }
    Ok(positional)
}

pub fn run(args: &[String]) -> ExitCode {
    let sub = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);
    if matches!(sub, Some("--help") | Some("-h") | Some("help"))
        || rest.iter().any(|a| a == "--help" || a == "-h")
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match sub {
        Some("build") => cmd_build(rest),
        Some("add") => cmd_add(rest),
        _ => usage_err("directory: expected a subcommand (build, add)"),
    }
}

fn write_directory(path: &str, dir: &WitnessDirectory) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(dir).map_err(|e| e.to_string())?;
    crate::witness_cmd::atomic_write_shared(Path::new(path), &json)
        .map_err(|e| format!("{path}: {e}"))
}

/// The fields of a registry entry: `REQUIRED` and `OPTIONAL` in
/// `registry/validate.py`.
const REQUIRED_FIELDS: [&str; 6] = [
    "name",
    "operator_org",
    "url",
    "pubkey",
    "runtime",
    "is_project_operated",
];
const OPTIONAL_FIELDS: [&str; 1] = ["compute_provider"];

/// The host of an `http(s)://` URL, lowercased, without port, userinfo or
/// IPv6 brackets (what Python's `urlsplit(url).hostname` returns).
fn url_host(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("");
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    host.to_ascii_lowercase()
}

/// `is_loopback` in `registry/validate.py`.
fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "0.0.0.0" | "::1" | "::")
        || host.starts_with("127.")
        || host.ends_with(".localhost")
}

/// Code points that render as nothing, or as a space that is not U+0020:
/// a label with one looks identical to one without it, yet the verifier
/// compares labels exactly. The same explicit list as `INVISIBLE` in
/// `registry/validate.py` (controls, format characters, invisible fillers,
/// variation selectors, private use, noncharacters), so both refuse exactly
/// the same text.
const INVISIBLE: [(u32, u32); 31] = [
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xE000, 0xF8FF),
    (0xFDD0, 0xFDEF),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
    (0xF0000, 0x10FFFF),
];

/// The code points of `text` in [`INVISIBLE`] (or U+xFFFE / U+xFFFF), as
/// `U+XXXX`.
fn invisible_chars(text: &str) -> Vec<String> {
    text.chars()
        .map(u32::from)
        .filter(|&o| {
            o & 0xFFFE == 0xFFFE || INVISIBLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&o))
        })
        .map(|o| format!("U+{o:04X}"))
        .collect()
}

/// `host` read as `inet_aton` reads it (`2130706433`, `0x7f.1` and `127.1`
/// are all 127.0.0.1 to getaddrinfo, curl and browsers), or `None` if it is
/// not a numeric IPv4 address. `numeric_ipv4` in `registry/validate.py`.
fn numeric_ipv4(host: &str) -> Option<u32> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut vals = Vec::with_capacity(parts.len());
    for p in &parts {
        let v = if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() {
                0
            } else {
                u64::from_str_radix(hex, 16).ok()?
            }
        } else if p.len() > 1 && p.starts_with('0') {
            u64::from_str_radix(p, 8).ok()?
        } else {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()?
        };
        vals.push(v);
    }
    let last_bits = 8 * (5 - vals.len() as u32);
    let (last, init) = vals.split_last()?;
    if init.iter().any(|&v| v > 255) || *last >= 1u64 << last_bits {
        return None;
    }
    let mut n: u64 = 0;
    for &v in init {
        n = n << 8 | v;
    }
    Some((n << last_bits | last) as u32)
}

/// Why a registry URL may not name `host`, or `None` for a name or a public
/// address written the ordinary way. `ip_literal_problem` in
/// `registry/validate.py`, with the same RFC 6890 blocks.
fn ip_literal_problem(host: &str) -> Option<String> {
    const BLOCKED_V4: [(u32, u32); 15] = [
        (0x0000_0000, 8),
        (0x0A00_0000, 8),
        (0x6440_0000, 10),
        (0x7F00_0000, 8),
        (0xA9FE_0000, 16),
        (0xAC10_0000, 12),
        (0xC000_0000, 24),
        (0xC000_0200, 24),
        (0xC058_6300, 24),
        (0xC0A8_0000, 16),
        (0xC612_0000, 15),
        (0xC633_6400, 24),
        (0xCB00_7100, 24),
        (0xE000_0000, 4),
        (0xF000_0000, 4),
    ];
    const BLOCKED_V6: [(&str, u32); 12] = [
        ("::", 96),
        ("::ffff:0:0", 96),
        ("64:ff9b::", 96),
        ("64:ff9b:1::", 48),
        ("100::", 64),
        ("2001::", 23),
        ("2001:db8::", 32),
        ("2002::", 16),
        ("fc00::", 7),
        ("fe80::", 10),
        ("fec0::", 10),
        ("ff00::", 8),
    ];
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.contains(':') {
        let Ok(ip) = host.parse::<std::net::Ipv6Addr>() else {
            return Some(format!("host {host:?} is not a valid IPv6 address"));
        };
        let ip = u128::from(ip);
        for (net, plen) in BLOCKED_V6 {
            let net = u128::from(net.parse::<std::net::Ipv6Addr>().expect("constant"));
            if ip >> (128 - plen) == net >> (128 - plen) {
                return Some(format!(
                    "host {host} is a non-public or IPv4-embedding IPv6 address"
                ));
            }
        }
        return None;
    }
    let n = numeric_ipv4(host)?;
    let dotted = std::net::Ipv4Addr::from(n).to_string();
    if host != dotted {
        return Some(format!(
            "host {host:?} is the IPv4 address {dotted} in another notation; write it as {dotted} (or use a name)"
        ));
    }
    for (net, plen) in BLOCKED_V4 {
        if n >> (32 - plen) == net >> (32 - plen) {
            return Some(format!("host {host} is not a public IPv4 address"));
        }
    }
    None
}

/// Every problem `registry/validate.py` reports for one entry offline, in
/// its words where it has them. `directory build` writes nothing unless
/// every entry has none: the directory is the trust anchor of each verdict
/// computed against it. `allow_insecure` accepts http:// and loopback URLs
/// (validate.py's `--allow-insecure`).
fn registry_entry_problems(v: &serde_json::Value, allow_insecure: bool) -> Vec<String> {
    let Some(obj) = v.as_object() else {
        return vec!["entry must be a JSON object".into()];
    };
    let missing: Vec<&str> = REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|f| !obj.contains_key(*f))
        .collect();
    if !missing.is_empty() {
        return vec![format!("missing {missing:?}")];
    }
    let mut problems = Vec::new();
    let mut unknown: Vec<&str> = obj
        .keys()
        .map(String::as_str)
        .filter(|k| !REQUIRED_FIELDS.contains(k) && !OPTIONAL_FIELDS.contains(k))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        problems.push(format!("unknown fields {unknown:?}"));
    }
    let text = |k: &str| obj.get(k).and_then(serde_json::Value::as_str);
    if !matches!(
        obj.get("compute_provider"),
        None | Some(serde_json::Value::Null | serde_json::Value::String(_))
    ) {
        problems.push("compute_provider must be a string or null".into());
    }
    for field in ["name", "operator_org", "compute_provider"] {
        let bad = invisible_chars(text(field).unwrap_or(""));
        if !bad.is_empty() {
            problems.push(format!(
                "{field} contains invisible or control characters ({}); labels are compared \
                 exactly, so they would make two labels that look the same differ",
                bad.join(", ")
            ));
        }
    }
    match text("pubkey") {
        Some(k) if k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()) => {
            if k.bytes().any(|b| b.is_ascii_uppercase()) {
                problems.push("pubkey must be lowercase".into());
            }
        }
        _ => problems.push(format!("pubkey {} must be 64 hex", obj["pubkey"])),
    }
    if !matches!(text("runtime"), Some("human" | "agent")) {
        problems.push("runtime must be human or agent".into());
    }
    match text("operator_org") {
        Some(org) if !org.trim().is_empty() && !org.trim().eq_ignore_ascii_case("unspecified") => {
            if org != org.split_whitespace().collect::<Vec<_>>().join(" ") {
                problems.push(format!(
                    "operator_org has leading, trailing or repeated whitespace ({org:?}); \
                     the label is compared byte for byte"
                ));
            }
        }
        _ => problems.push("operator_org must name the organisation that runs the key".into()),
    }
    if !obj["is_project_operated"].is_boolean() {
        problems.push("is_project_operated must be a boolean".into());
    }
    match text("url") {
        Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
            let host = url_host(url);
            if host.is_empty() {
                problems.push(format!("url {url} has no host"));
            }
            if url.starts_with("http://") && !allow_insecure {
                problems.push(format!(
                    "url {url} is plain http; a registry entry must be https \
                     (http is accepted only with --allow-insecure, for tests)"
                ));
            }
            if is_loopback(&host) && !allow_insecure {
                problems.push(format!(
                    "url {url} is a loopback address; give the public URL clients reach"
                ));
            } else if !allow_insecure {
                if let Some(why) = ip_literal_problem(&host) {
                    problems.push(format!("url {url}: {why}"));
                }
            }
        }
        _ => problems.push("url must be http(s)".into()),
    }
    match text("name") {
        Some(n) if !n.is_empty() && !n.contains('+') && !n.chars().any(char::is_whitespace) => {}
        _ => problems.push("name is a C2SP key name: non-empty, no whitespace, no '+'".into()),
    }
    problems
}

/// Problems with an entry that `directory add` refuses; `directory build`
/// applies all of `registry_entry_problems`.
fn entry_problem(e: &WitnessEntry) -> Option<String> {
    if !crate::is_hex32(e.pubkey.trim()) {
        return Some(format!("pubkey {:?} is not 64 hex characters", e.pubkey));
    }
    if e.name.is_empty() || e.name.contains('+') || e.name.chars().any(char::is_whitespace) {
        return Some(format!("name {:?} is not a C2SP key name", e.name));
    }
    let org = e.operator_org.trim();
    if org.is_empty() || org.eq_ignore_ascii_case("unspecified") {
        return Some("operator_org must name the organisation that runs the key".into());
    }
    if !(e.url.starts_with("http://") || e.url.starts_with("https://")) {
        return Some(format!("url {:?} is not http(s)", e.url));
    }
    None
}

fn cmd_build(args: &[String]) -> ExitCode {
    let positional = match check_flags(
        args,
        &["--registry", "--url", "--out"],
        &["--include-project", "--allow-insecure"],
    ) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("directory build: {e}")),
    };
    if !positional.is_empty() {
        return usage_err(&format!(
            "directory build: unexpected argument {:?}",
            positional[0]
        ));
    }
    let Some(out) = crate::flag_value(args, "--out") else {
        return usage_err("directory build: --out <trusted.json> is required");
    };
    let registry = crate::flag_value(args, "--registry");
    let url = crate::flag_value(args, "--url");
    if registry.is_some() && url.is_some() {
        return usage_err("directory build: give --registry or --url, not both");
    }
    let include_project = args.iter().any(|a| a == "--include-project");
    let allow_insecure = args.iter().any(|a| a == "--allow-insecure");

    // Each source yields (label, entry as parsed JSON) so a bad entry is
    // reported by where it came from.
    let mut sources: Vec<(String, serde_json::Value)> = Vec::new();
    match (&registry, &url) {
        (_, Some(u)) => {
            // The document fetched is the trust anchor; over plain http
            // anyone on the path can add witnesses to it.
            if u.starts_with("http://") && !allow_insecure {
                return usage_err(&format!(
                    "directory build: --url {u} is plain http; the directory you trust must be \
                     fetched over https (--allow-insecure accepts http, for local tests)"
                ));
            }
            let parsed = match crate::http::parse_url(u) {
                Ok(p) => p,
                Err(e) => return usage_err(&format!("directory build: {e}")),
            };
            // `parse_url` keeps the document path as `base_path`; a bare
            // host needs "/" as the request target.
            let target = if parsed.base_path.is_empty() { "/" } else { "" };
            let (status, body, _) = match crate::http::request(
                &parsed,
                "GET",
                target,
                b"",
                std::time::Duration::from_secs(10),
            ) {
                Ok(r) => r,
                Err(e) => return fail(format!("{u}: {e}")),
            };
            if status != 200 {
                return fail(format!("{u}: HTTP {status}"));
            }
            let doc: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return fail(format!("{u}: not JSON: {e}")),
            };
            let list = match doc.get("witnesses").or(Some(&doc)) {
                Some(serde_json::Value::Array(a)) => a.clone(),
                _ => {
                    return fail(format!(
                        "{u}: expected {{\"witnesses\": [...]}} or a JSON array of entries"
                    ))
                }
            };
            for (i, v) in list.into_iter().enumerate() {
                sources.push((format!("{u}#{i}"), v));
            }
        }
        (reg, None) => {
            let dir = reg
                .clone()
                .unwrap_or_else(|| "registry/witnesses".to_string());
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    return fail(format!(
                        "{dir}: {e}\n  (pass --registry <dir of witness JSON files>, or --url)"
                    ))
                }
            };
            let mut paths: Vec<std::path::PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            paths.sort();
            for p in paths {
                let label = p.display().to_string();
                let raw = match crate::read_input(&label) {
                    Ok(r) => r,
                    Err(e) => return fail(format!("{label}: {e}")),
                };
                match serde_json::from_str::<serde_json::Value>(&raw) {
                    Ok(v) => sources.push((label, v)),
                    Err(e) => return fail(format!("{label}: not JSON: {e}")),
                }
            }
        }
    }

    // Every entry is checked, and every problem reported, before anything
    // is written: like `registry/validate.py`, not first-error-only.
    let mut directory = WitnessDirectory::default();
    let mut problems: Vec<String> = Vec::new();
    let mut seen_keys = std::collections::HashMap::new();
    let mut seen_names = std::collections::HashMap::new();
    let mut dropped_project = 0usize;
    let total = sources.len();
    for (label, value) in sources {
        let entry_problems = registry_entry_problems(&value, allow_insecure);
        if !entry_problems.is_empty() {
            problems.extend(entry_problems.into_iter().map(|p| format!("{label}: {p}")));
            continue;
        }
        let entry: WitnessEntry = match serde_json::from_value(value) {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!("{label}: not a directory entry: {e}"));
                continue;
            }
        };
        if let Some(prev) = seen_keys.insert(entry.pubkey.clone(), label.clone()) {
            problems.push(format!("{label}: duplicate pubkey, also in {prev}"));
        }
        if let Some(prev) = seen_names.insert(entry.name.clone(), label.clone()) {
            problems.push(format!("{label}: duplicate name, also in {prev}"));
        }
        if entry.is_project_operated && !include_project {
            dropped_project += 1;
            continue;
        }
        directory.witnesses.push(entry);
    }
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("error: {p}");
        }
        return fail(format!(
            "refusing to build {out}: {} problem(s) in {total} entries (the offline checks of \
             registry/validate.py; --allow-insecure accepts http:// and loopback URLs)",
            problems.len()
        ));
    }
    if let Err(e) = write_directory(&out, &directory) {
        return fail(e);
    }
    let orgs = directory.distinct_operator_count();
    eprintln!(
        "wrote {out}: {} witness{} from {orgs} operator{}{}",
        directory.witnesses.len(),
        if directory.witnesses.len() == 1 {
            ""
        } else {
            "es"
        },
        if orgs == 1 { "" } else { "s" },
        if dropped_project > 0 {
            format!(" ({dropped_project} project-operated left out; --include-project keeps them)")
        } else {
            String::new()
        }
    );
    if orgs < witness_log_network::MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED {
        eprintln!(
            "note: WITNESSED needs cosignatures from at least {} distinct operators; this directory has {orgs}",
            witness_log_network::MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED
        );
    }
    ExitCode::SUCCESS
}

fn cmd_add(args: &[String]) -> ExitCode {
    let positional = match check_flags(
        args,
        &["--vkey", "--org", "--url", "--compute"],
        &["--project-operated"],
    ) {
        Ok(p) => p,
        Err(e) => return usage_err(&format!("directory add: {e}")),
    };
    let [path] = positional.as_slice() else {
        return usage_err("directory add: expected <trusted.json>");
    };
    let (Some(vkey), Some(org), Some(url)) = (
        crate::flag_value(args, "--vkey"),
        crate::flag_value(args, "--org"),
        crate::flag_value(args, "--url"),
    ) else {
        return usage_err("directory add: --vkey, --org and --url are all required");
    };
    let vk = match VerifierKey::parse(&vkey) {
        Ok(v) => v,
        Err(e) => return usage_err(&format!("directory add: bad vkey: {e}")),
    };
    if vk.sig_type != SIG_TYPE_COSIGNATURE_V1 {
        return usage_err(
            "directory add: this is a log (signature) key, not a witness cosignature key; a witness's vkey is what `witness init` prints and GET / serves",
        );
    }
    let entry = WitnessEntry::independent(
        vk.name.clone(),
        org,
        url,
        hex::encode(&vk.public_key),
        crate::flag_value(args, "--compute"),
    );
    let mut entry = entry;
    if args.iter().any(|a| a == "--project-operated") {
        entry.is_project_operated = true;
    }
    if let Some(problem) = entry_problem(&entry) {
        return usage_err(&format!("directory add: {problem}"));
    }
    let mut directory = if Path::new(path).exists() {
        match crate::read_input(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| crate::parse_directory(&raw))
        {
            Ok(d) => d,
            Err(e) => return fail(format!("{path}: {e}")),
        }
    } else {
        WitnessDirectory::default()
    };
    if directory
        .witnesses
        .iter()
        .any(|w| w.pubkey.eq_ignore_ascii_case(&entry.pubkey))
    {
        return fail(format!(
            "{path}: a witness with key {} is already listed",
            crate::short(&entry.pubkey)
        ));
    }
    directory.witnesses.push(entry);
    if let Err(e) = write_directory(path, &directory) {
        return fail(e);
    }
    eprintln!(
        "added {} to {path} ({} witness{}, {} operator{})",
        vk.name,
        directory.witnesses.len(),
        if directory.witnesses.len() == 1 {
            ""
        } else {
            "es"
        },
        directory.distinct_operator_count(),
        if directory.distinct_operator_count() == 1 {
            ""
        } else {
            "s"
        }
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod registry_check_tests {
    //! Re-audit of the 0.6.1 fixes: `directory build` and
    //! `registry/validate.py` must refuse the same entries. The cases and
    //! answers here are the ones registry/tests/test_validate.py checks.
    use super::*;

    fn entry(field: &str, value: serde_json::Value) -> serde_json::Value {
        let mut e = serde_json::json!({
            "name": "w1.example.org/w",
            "operator_org": "Org A",
            "url": "https://w1.example.org",
            "pubkey": "ab".repeat(32),
            "runtime": "human",
            "is_project_operated": false,
        });
        e[field] = value;
        e
    }

    #[test]
    fn numeric_ipv4_reads_what_inet_aton_reads() {
        for (host, want) in [
            ("2130706433", Some(0x7F00_0001)),
            ("0x7f.1", Some(0x7F00_0001)),
            ("127.1", Some(0x7F00_0001)),
            ("0177.0.0.1", Some(0x7F00_0001)),
            ("0x", Some(0)),
            ("0.0x0.0.0", Some(0)),
            ("0x7_f.1", None),
            ("09.1.1.1", None),
            ("1.2.3.4.5", None),
            ("256.1.1.1", None),
            ("deadbeef", None),
            ("w1.example.org", None),
        ] {
            assert_eq!(numeric_ipv4(host), want, "{host}");
        }
    }

    #[test]
    fn non_public_or_disguised_ip_literals_are_refused() {
        for url in [
            "https://169.254.169.254/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://127.1/",
            "https://[::ffff:127.0.0.1]/",
            "https://[64:ff9b::a9fe:a9fe]/",
            "https://10.0.0.5/",
            "https://100.64.0.1/",
            "https://[fe80::1]/",
            "https://[fc00::1]/",
            "https://169.254.169.254./",
            "https://01.2.3.4/",
        ] {
            let p = registry_entry_problems(&entry("url", url.into()), false);
            assert!(p.iter().any(|p| p.contains("url")), "{url}: {p:?}");
            assert!(
                registry_entry_problems(&entry("url", url.into()), true).is_empty(),
                "{url} with --allow-insecure"
            );
        }
        for url in [
            "https://93.184.216.34/",
            "https://[2606:4700::1]:8443/",
            "https://deadbeef.example/",
        ] {
            let p = registry_entry_problems(&entry("url", url.into()), false);
            assert!(p.is_empty(), "{url}: {p:?}");
        }
    }

    #[test]
    fn invisible_characters_in_a_label_are_refused() {
        for org in [
            "Org\u{200b}A",
            "Org A\u{200d}",
            "\u{feff}Org A",
            "Org\u{ad}A",
            "Org\u{2066}A\u{2069}",
            "Org\u{3164}A",
            "Org A\u{fe0f}",
            "Org\u{7}A",
            "Org\u{e000}A",
        ] {
            let p = registry_entry_problems(&entry("operator_org", org.into()), false);
            assert!(
                p.iter()
                    .any(|p| p.contains("invisible or control characters")),
                "{org:?}: {p:?}"
            );
        }
        assert!(registry_entry_problems(
            &entry("operator_org", "株式会社 Ejemplo Ñandú".into()),
            false
        )
        .is_empty());
    }

    #[test]
    fn fields_must_have_their_json_type() {
        for (field, value) in [
            ("operator_org", serde_json::json!(["Org A"])),
            ("name", serde_json::json!(7)),
            ("url", serde_json::Value::Null),
            ("pubkey", serde_json::json!(1)),
            ("compute_provider", serde_json::json!(123)),
        ] {
            let p = registry_entry_problems(&entry(field, value.clone()), false);
            assert!(
                p.iter().any(|p| p.contains(field)),
                "{field}={value}: {p:?}"
            );
        }
    }
}
