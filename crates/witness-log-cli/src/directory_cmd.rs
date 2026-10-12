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
  witness-log directory build [--registry DIR | --url URL] [--include-project] --out trusted.json
      Collect DIR/*.json (one directory entry per file, as `witness init` prints
      them; default DIR is ./registry/witnesses) or a directory document fetched
      from URL (http://) into {\"witnesses\": [...]}. Project-operated entries are
      left out unless --include-project.
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

/// Problems with an entry that `registry/validate.py` would also reject.
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
        &["--include-project"],
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

    // Each source yields (label, entry as parsed JSON) so a bad entry is
    // reported by where it came from.
    let mut sources: Vec<(String, serde_json::Value)> = Vec::new();
    match (&registry, &url) {
        (_, Some(u)) => {
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

    let mut directory = WitnessDirectory::default();
    let mut seen_keys = std::collections::HashMap::new();
    let mut dropped_project = 0usize;
    for (label, value) in sources {
        let entry: WitnessEntry = match serde_json::from_value(value) {
            Ok(e) => e,
            Err(e) => return fail(format!("{label}: not a directory entry: {e}")),
        };
        if let Some(problem) = entry_problem(&entry) {
            return fail(format!("{label}: {problem}"));
        }
        let key = entry.pubkey.to_ascii_lowercase();
        if let Some(prev) = seen_keys.insert(key, label.clone()) {
            return fail(format!("{label}: duplicate pubkey, also in {prev}"));
        }
        if entry.is_project_operated && !include_project {
            dropped_project += 1;
            continue;
        }
        directory.witnesses.push(entry);
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
