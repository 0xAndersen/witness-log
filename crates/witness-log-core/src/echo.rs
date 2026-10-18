//! Untrusted input in a message, bounded.
//!
//! A verifier says why an input failed, and the input is untrusted: a
//! dossier field, or a `serde_json` error that quotes one, can be
//! megabytes long. Echoed whole, it is copied into every report, log line
//! and exception that carries the message (an outside audit of 0.6.1 found
//! a 10-million-digit literal returned in full in `failures[0]`). These
//! keep the start of the input and say how long it was. The Go and
//! TypeScript verifiers bound their messages the same way; the wording of
//! a failure is not normative (SPEC.md §9.2), only whether there is one.

/// How many characters of an input [`quoted`] keeps.
pub const MAX_ECHO_CHARS: usize = 64;

/// The longest message, in characters, that [`bounded`] returns unchanged.
pub const MAX_MESSAGE_CHARS: usize = 320;

const HEAD_CHARS: usize = 128;
const TAIL_CHARS: usize = 160;

/// `s` as `{:?}` prints it when it has at most [`MAX_ECHO_CHARS`]
/// characters; otherwise its first [`MAX_ECHO_CHARS`] characters, quoted,
/// then `…` and its length in bytes.
pub fn quoted(s: &str) -> String {
    match s.char_indices().nth(MAX_ECHO_CHARS) {
        None => format!("{s:?}"),
        Some((cut, _)) => format!(
            "{:?}… ({} bytes)",
            s.get(..cut).unwrap_or_default(),
            s.len()
        ),
    }
}

/// A message that may embed untrusted input (a `serde_json` error quotes
/// the string or variant name it refused): unchanged up to
/// [`MAX_MESSAGE_CHARS`] characters, otherwise its first 128 and last 160
/// characters around a note of how many bytes were left out. The tail is
/// kept because that is where `serde_json` says what it expected and
/// where (`expected u64 at line 1 column 9`).
pub fn bounded(msg: &str) -> String {
    let chars = msg.chars().count();
    if chars <= MAX_MESSAGE_CHARS {
        return msg.to_string();
    }
    let head: String = msg.chars().take(HEAD_CHARS).collect();
    let tail: String = msg.chars().skip(chars - TAIL_CHARS).collect();
    let elided = msg.len() - head.len() - tail.len();
    format!("{head} … [{elided} bytes elided] … {tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_is_echoed_whole() {
        assert_eq!(quoted("abc"), "\"abc\"");
        let s = "é".repeat(MAX_ECHO_CHARS);
        assert_eq!(quoted(&s), format!("{s:?}"));
        assert_eq!(bounded("expected u64"), "expected u64");
    }

    #[test]
    fn long_input_keeps_its_start_and_its_length() {
        let s = "1".repeat(10_000_000);
        let q = quoted(&s);
        assert_eq!(q, format!("\"{}\"… (10000000 bytes)", "1".repeat(64)));
        // Multi-byte characters are never split.
        let s = "é".repeat(100);
        assert_eq!(quoted(&s), format!("\"{}\"… (200 bytes)", "é".repeat(64)));
    }

    #[test]
    fn a_long_message_keeps_its_head_and_tail() {
        let msg = format!(
            "invalid type: string \"{}\", expected u64 at line 1 column 10000024",
            "a".repeat(10_000_000)
        );
        let b = bounded(&msg);
        assert!(b.chars().count() <= MAX_MESSAGE_CHARS + 40, "{}", b.len());
        assert!(b.starts_with("invalid type: string \"aaaa"));
        assert!(b.ends_with("\", expected u64 at line 1 column 10000024"));
        assert!(b.contains("bytes elided"));
    }
}
