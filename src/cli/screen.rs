use crate::command::manifest::Permissions;

pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            let hidden = (c.is_control() && c != '\n' && c != '\t')
                || matches!(
                    c,
                    '\u{061c}'
                        | '\u{200b}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{feff}'
                );
            if hidden { c.escape_unicode().to_string() } else { c.to_string() }
        })
        .collect()
}

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
        ..perms.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_escapes_what_a_terminal_would_hide() {
        for hidden in ['\u{1b}', '\r', '\u{202e}', '\u{2066}', '\u{061c}', '\u{200b}', '\u{2060}', '\u{feff}'] {
            assert_eq!(printable(&format!("a{hidden}b")), format!("a{}b", hidden.escape_unicode()));
        }
        assert_eq!(printable("line\n\tnext ø ✓"), "line\n\tnext ø ✓");
    }
}
