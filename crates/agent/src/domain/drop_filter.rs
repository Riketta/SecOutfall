//! Drop extension filter with legacy conventions (`*` = all, `none` =
//! extensionless, dots optional, case-insensitive).

/// Parsed drop extension filter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DropFilter {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// `*` — every file matches.
    All,
    /// `none` — extensionless files match.
    Extensionless,
    /// A specific extension, normalized (lowercase, no leading dot).
    Extension(String),
}

impl DropFilter {
    /// Parse the filter from configured extension tokens.
    ///
    /// An empty token list matches nothing (secure default: explicit opt-in).
    #[must_use]
    pub fn new(extensions: &[String]) -> Self {
        let rules = extensions
            .iter()
            .filter_map(|raw| {
                let token = raw.trim().to_lowercase();
                match token.as_str() {
                    "" => None,
                    "*" => Some(Rule::All),
                    "none" => Some(Rule::Extensionless),
                    _ => Some(Rule::Extension(token.trim_start_matches('.').to_owned())),
                }
            })
            .collect();
        Self { rules }
    }

    /// Does this file path pass the filter?
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let extension =
            std::path::Path::new(path).extension().map(|ext| ext.to_string_lossy().to_lowercase());
        self.rules.iter().any(|rule| match rule {
            Rule::All => true,
            Rule::Extensionless => extension.as_ref().is_none_or(String::is_empty),
            Rule::Extension(expected) => extension.as_ref().is_some_and(|ext| ext == expected),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn filter(tokens: &[&str]) -> DropFilter {
        DropFilter::new(&tokens.iter().map(ToString::to_string).collect::<Vec<String>>())
    }

    #[test]
    fn star_matches_everything() {
        let f = filter(&["*"]);
        assert!(f.matches("C:\\x.txt"));
        assert!(f.matches("C:\\x"));
        assert!(f.matches("no-extension"));
    }

    #[test]
    fn none_means_extensionless() {
        let f = filter(&["none", ".txt"]);
        assert!(f.matches("C:\\plain"));
        assert!(f.matches("C:\\trailing."));
        assert!(f.matches("C:\\doc.TXT"));
        assert!(!f.matches("C:\\doc.dll"));
    }

    #[test]
    fn dots_and_case_are_normalized() {
        let f = filter(&["TXT", ".Dll"]);
        assert!(f.matches("C:\\a.txt"));
        assert!(f.matches("C:\\a.DLL"));
        assert!(!f.matches("C:\\a.bat"));
    }

    #[test]
    fn empty_filter_matches_nothing() {
        let f = DropFilter::default();
        assert!(!f.matches("C:\\a.txt"));
        assert!(!f.matches("C:\\a"));
    }
}
