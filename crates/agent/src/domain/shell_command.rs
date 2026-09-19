//! Shell "open" command substitution — pure logic, no Windows dependency.
//!
//! Extracted from the registry adapter so it is unit-testable on every
//! platform (Linux CI compiles and tests it). This is the root-cause fix for
//! legacy bug #7: the legacy code split the association command on spaces,
//! crashing on single-token commands and mangling quoted executables.

/// Substitution failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShellCommandError {
    /// The registry yielded an empty/whitespace command string.
    #[error("shell command is empty")]
    Empty,
}

/// Substitute the document into a registry `shell\open\command` string.
///
/// Windows conventions implemented:
/// - `%1` (and its long-path alias `%L`, case-insensitive) is replaced with
///   the document path **as-is** — the template's own quotes provide the
///   quoting (this is what `ShellExecute` does; double-quoting here would
///   produce `""path""`).
/// - If no placeholder is present, the quoted document is appended (the
///   default drop-target behavior).
/// - `%*`, `%2`.. remain untouched (DDE leftovers).
///
/// The command string is passed through otherwise — the registry is
/// authoritative; we substitute, not sanitize (a broken association produces
/// the same failure Windows itself would produce).
///
/// # Errors
/// [`ShellCommandError::Empty`] when the command is blank.
pub fn substitute_command(command: &str, document: &str) -> Result<String, ShellCommandError> {
    if command.trim().is_empty() {
        return Err(ShellCommandError::Empty);
    }

    let mut result = String::with_capacity(command.len() + document.len() + 3);
    let mut index = 0;
    while let Some(rest) = command.get(index..) {
        // `%1` or its long-path alias `%L`, case-insensitive.
        if rest.starts_with("%1") || rest.starts_with("%l") || rest.starts_with("%L") {
            result.push_str(document);
            index += 2;
        } else {
            let Some(chunk) = rest.chars().next() else { break };
            result.push(chunk);
            index += chunk.len_utf8();
        }
    }

    if !result.contains(document) {
        result.push(' ');
        result.push('"');
        result.push_str(document);
        result.push('"');
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const DOC: &str = "C:\\Samples\\evil script.js";

    #[test]
    fn placeholder_is_replaced_with_document_path() {
        // The template's own quotes provide the quoting (ShellExecute semantics).
        let out = substitute_command("\"C:\\Program Files\\App\\run.exe\" \"%1\"", DOC).unwrap();
        assert_eq!(out, format!("\"C:\\Program Files\\App\\run.exe\" \"{DOC}\""));
    }

    #[test]
    fn unquoted_placeholder_is_substituted_verbatim() {
        // Faithful to the registry: an unquoted `%1` stays unquoted, exactly
        // like Windows itself (spaces then split — the association's problem).
        let out = substitute_command("C:\\Tools\\view.exe %1", DOC).unwrap();
        assert_eq!(out, format!("C:\\Tools\\view.exe {DOC}"));
    }

    #[test]
    fn single_token_command_gets_document_appended() {
        // Legacy bug #7: this input used to crash the legacy agent.
        let out = substitute_command("notepad.exe", DOC).unwrap();
        assert_eq!(out, format!("notepad.exe \"{DOC}\""));
    }

    #[test]
    fn long_path_alias_is_also_substituted() {
        let out = substitute_command("C:\\Tools\\view.exe %L", DOC).unwrap();
        assert_eq!(out, format!("C:\\Tools\\view.exe {DOC}"));
    }

    #[test]
    fn lowercase_long_path_alias_is_also_substituted() {
        let out = substitute_command("C:\\Tools\\view.exe %l", DOC).unwrap();
        assert_eq!(out, format!("C:\\Tools\\view.exe {DOC}"));
    }

    #[test]
    fn document_quoted_inside_larger_arg_is_substituted_once() {
        let out = substitute_command("app.exe /doc:\"%1\" /flag", DOC).unwrap();
        assert_eq!(out, format!("app.exe /doc:\"{DOC}\" /flag"));
    }

    #[test]
    fn unicode_document_survives_substitution() {
        let doc = "C:\\Выбор\\малица.js";
        let out = substitute_command("app.exe \"%1\"", doc).unwrap();
        assert_eq!(out, format!("app.exe \"{doc}\""));
        let out = substitute_command("app.exe", doc).unwrap();
        assert_eq!(out, format!("app.exe \"{doc}\""));
    }

    #[test]
    fn empty_command_is_rejected() {
        assert_eq!(substitute_command("   ", DOC), Err(ShellCommandError::Empty));
        assert_eq!(substitute_command("", DOC), Err(ShellCommandError::Empty));
    }

    #[test]
    fn dde_placeholders_pass_through() {
        let out = substitute_command("app.exe %2 %*", DOC).unwrap();
        assert_eq!(out, format!("app.exe %2 %* \"{DOC}\""));
    }
}
