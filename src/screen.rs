//! Text from manifests, scripts and repos, made safe to show on a terminal.

use crate::manifest::Permissions;

/// Escapes characters that could hide or reorder text on a terminal: ANSI
/// escapes, carriage returns and bidi overrides ("Trojan Source").
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            let hidden = (c.is_control() && c != '\n' && c != '\t')
                || matches!(
                    c,
                    '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
                );
            if hidden { c.escape_unicode().to_string() } else { c.to_string() }
        })
        .collect()
}

/// Only a script may span lines. A newline in a manifest field could print a
/// fake line, like a second, harmless-looking `permissions:`.
pub fn one_line(text: &str) -> String {
    text.replace('\n', "\\n").replace('\t', "\\t")
}

pub fn one_line_permissions(perms: &Permissions) -> Permissions {
    let all = |values: &[String]| values.iter().map(|v| one_line(v)).collect();
    Permissions {
        http: all(&perms.http),
        vault: all(&perms.vault),
        exec: all(&perms.exec),
        env: all(&perms.env),
        read: all(&perms.read),
        write: all(&perms.write),
    }
}
