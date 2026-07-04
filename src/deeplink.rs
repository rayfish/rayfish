//! Shared `rayfish://` deep-link parser. Platform-agnostic: Android intents,
//! iOS URL handling, and the desktop `ray open` subcommand all route through it.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RayfishLink {
    Join(String),
    Pair(String),
}

/// Parses `rayfish://<verb>/<code>` where verb is `join` or `pair`. Tolerant of
/// surrounding whitespace and a single trailing slash. The code is taken verbatim
/// (not percent-decoded); invite/pairing codes are bs58 and never contain
/// reserved characters.
pub fn parse_rayfish_uri(s: &str) -> anyhow::Result<RayfishLink> {
    let s = s.trim();
    let rest = s
        .strip_prefix("rayfish://")
        .ok_or_else(|| anyhow::anyhow!("not a rayfish:// URI"))?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (verb, code) = rest
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing code in {s}"))?;
    anyhow::ensure!(!code.is_empty(), "empty code in {s}");
    match verb {
        "join" => Ok(RayfishLink::Join(code.to_string())),
        "pair" => Ok(RayfishLink::Pair(code.to_string())),
        other => anyhow::bail!("unknown rayfish verb {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_join_and_pair() {
        assert_eq!(
            parse_rayfish_uri("rayfish://join/ABC123").unwrap(),
            RayfishLink::Join("ABC123".into())
        );
        assert_eq!(
            parse_rayfish_uri("rayfish://pair/XYZ789").unwrap(),
            RayfishLink::Pair("XYZ789".into())
        );
    }

    #[test]
    fn trailing_slash_and_whitespace_tolerated() {
        assert_eq!(
            parse_rayfish_uri(" rayfish://join/CODE/ ").unwrap(),
            RayfishLink::Join("CODE".into())
        );
    }

    #[test]
    fn rejects_bad_scheme_host_or_missing_code() {
        assert!(parse_rayfish_uri("https://join/x").is_err());
        assert!(parse_rayfish_uri("rayfish://bogus/x").is_err());
        assert!(parse_rayfish_uri("rayfish://join/").is_err());
        assert!(parse_rayfish_uri("rayfish://join").is_err());
    }
}
