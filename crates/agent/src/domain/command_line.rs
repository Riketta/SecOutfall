//! Windows command-line splitting — pure logic, no Windows dependency.
//!
//! `ShellExecute`-resolved association commands arrive as full command lines
//! (`"C:\...\wscript.exe" "C:\sample\evil.js" /flag`). Launching needs them
//! split into program + argv with `CommandLineToArgvW` semantics so the
//! launcher adapters can re-quote per mechanism.
//!
//! Implemented rules:
//! - whitespace separates arguments outside quotes;
//! - `"` toggles in-quote mode; `""` inside quotes yields a literal quote;
//! - backslashes: `2n` before a quote = `n` backslashes + quote acts as
//!   delimiter/toggle; `2n+1` before a quote = `n` backslashes + literal quote.

/// Split a Windows-style command line into argv (argv\[0\] = program).
#[must_use]
pub fn split_command_line(line: &str) -> Vec<String> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    let mut backslashes = 0_usize;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                if backslashes % 2 == 0 {
                    // Even run: the quote is a delimiter/toggle; backslashes pass.
                    for _ in 0..backslashes / 2 {
                        current.push('\\');
                    }
                    if in_quotes && chars.peek() == Some(&'"') {
                        current.push('"');
                        let _ = chars.next();
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    // Odd run: the quote is literal (n = backslashes / 2).
                    for _ in 0..backslashes / 2 {
                        current.push('\\');
                    }
                    current.push('"');
                }
                backslashes = 0;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                for _ in 0..backslashes {
                    current.push('\\');
                }
                // A run of backslashes alone still forms a token (`a b \\\\`
                // must yield `a`, `b`, `\\\\` — CommandLineToArgvW parity).
                if has_token || !current.is_empty() {
                    argv.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                for _ in 0..backslashes {
                    current.push('\\');
                }
                backslashes = 0;
                current.push(c);
                has_token = true;
            }
        }
    }
    for _ in 0..backslashes {
        current.push('\\');
    }
    if has_token || !current.is_empty() {
        argv.push(current);
    }
    argv
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn plain_tokens_split_on_whitespace() {
        assert_eq!(split_command_line("app.exe a b"), ["app.exe", "a", "b"]);
        assert_eq!(split_command_line("  app.exe   "), ["app.exe"]);
        assert_eq!(split_command_line(""), Vec::<String>::new());
    }

    #[test]
    fn quoted_paths_stay_one_token() {
        let argv = split_command_line("\"C:\\Program Files\\App\\run.exe\" \"%1\" /flag");
        assert_eq!(argv, ["C:\\Program Files\\App\\run.exe", "%1", "/flag"]);
    }

    #[test]
    fn empty_quotes_yield_empty_token() {
        assert_eq!(split_command_line("app.exe \"\" x"), ["app.exe", "", "x"]);
    }

    #[test]
    fn doubled_quotes_inside_quotes_are_literal() {
        assert_eq!(split_command_line("\"a\"\"b\""), ["a\"b"]);
    }

    #[test]
    fn backslash_runs_follow_argv_rules() {
        // 2n backslashes + quote: n backslashes, quote toggles.
        assert_eq!(split_command_line("a\\\\\"b"), ["a\\b"]);
        // 2n+1 backslashes + quote: n backslashes + literal quote.
        assert_eq!(split_command_line("a\\\\\\\"b"), ["a\\\"b"]);
        // Trailing backslashes are literal.
        assert_eq!(split_command_line("C:\\dir\\"), ["C:\\dir\\"]);
    }

    #[test]
    fn lone_backslash_token_is_not_dropped() {
        // A trailing backslash-only argument must survive the split
        // (CommandLineToArgvW parity): input `a b \\` splits to a, b, `\\`.
        assert_eq!(split_command_line("a b \\\\"), ["a", "b", "\\\\"]);
        // Quoted-space then a backslash-only tail: input `x " " \\\\`
        // splits to x, (space), `\\`.
        assert_eq!(split_command_line(concat!("x \" \" ", "\\\\")), ["x", " ", "\\\\"]);
    }
}
