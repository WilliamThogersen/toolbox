//! JSON string escapes undone in any text, so a key a response wrote as `\uXXXX`
//! or `\/` can be found, and what was found mapped back to where it sits.

use std::ops::Range;

/// `source` with one layer of JSON string escapes undone.
pub struct Unescaped {
    pub text: String,
    /// `(position in text, position in source)` at the start and right after each
    /// undone escape. Between two of them both texts match byte for byte.
    anchors: Vec<(usize, usize)>,
}

impl Unescaped {
    /// Undoes every escape JSON knows, wherever it is: inside a string or not, in a
    /// JSON body or any other text. A backslash that starts no escape stays as it is.
    pub fn new(source: &str) -> Self {
        let mut text = String::with_capacity(source.len());
        let mut anchors = vec![(0, 0)];
        let mut rest = 0;
        while let Some(found) = source[rest..].find('\\') {
            let at = rest + found;
            text.push_str(&source[rest..at]);
            match decode_escape(&source[at..]) {
                Some((decoded, len)) => {
                    text.push(decoded);
                    rest = at + len;
                    anchors.push((text.len(), rest));
                }
                None => {
                    text.push('\\');
                    rest = at + 1;
                }
            }
        }
        text.push_str(&source[rest..]);
        Self { text, anchors }
    }

    pub fn changed(&self) -> bool {
        self.anchors.len() > 1
    }

    /// The part of `source` that `range` of `text` was decoded from. `range` must
    /// start and end on character boundaries, as `str` matches do.
    pub fn source_range(&self, range: Range<usize>) -> Range<usize> {
        self.source_position(range.start)..self.source_position(range.end)
    }

    fn source_position(&self, at: usize) -> usize {
        // `(0, 0)` comes first, so there is always an anchor at or before `at`.
        let index = self.anchors.partition_point(|(decoded, _)| *decoded <= at) - 1;
        let (decoded, source) = self.anchors[index];
        source + (at - decoded)
    }
}

/// `text` unescaped again and again, for JSON inside a JSON string, at most `layers`
/// deep. Stops early once a layer has no escape left.
pub fn layers(text: &str, layers: usize) -> Vec<Unescaped> {
    let mut found: Vec<Unescaped> = Vec::new();
    while found.len() < layers {
        let source = found.last().map_or(text, |layer| layer.text.as_str());
        if !source.contains('\\') {
            break;
        }
        let layer = Unescaped::new(source);
        if !layer.changed() {
            break;
        }
        found.push(layer);
    }
    found
}

/// The character the escape at the start of `s` stands for, and its length in bytes.
fn decode_escape(s: &str) -> Option<(char, usize)> {
    let simple = match s.as_bytes().get(1)? {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => return decode_unicode(s),
        _ => return None,
    };
    Some((simple, 2))
}

/// `\uXXXX`, or two of them in a row (a surrogate pair) for a character outside the
/// basic plane, like an emoji.
fn decode_unicode(s: &str) -> Option<(char, usize)> {
    let high = hex4(s.get(2..6)?)?;
    if let Some(decoded) = char::from_u32(high) {
        return Some((decoded, 6));
    }
    let low = s
        .get(6..12)
        .filter(|next| next.starts_with("\\u"))
        .and_then(|next| hex4(&next[2..]))?;
    let pair = (0xD800..0xDC00).contains(&high) && (0xDC00..0xE000).contains(&low);
    let decoded = pair
        .then(|| char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)))
        .flatten()?;
    Some((decoded, 12))
}

fn hex4(digits: &str) -> Option<u32> {
    let valid = digits.len() == 4 && digits.bytes().all(|b| b.is_ascii_hexdigit());
    valid.then(|| u32::from_str_radix(digits, 16).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_map_back_across_escapes() {
        let source = r#"ab\/c\"d"#;
        let layer = Unescaped::new(source);
        assert_eq!(layer.text, r#"ab/c"d"#);
        let at = layer.text.find("/c\"").unwrap();
        assert_eq!(&source[layer.source_range(at..at + 3)], r#"\/c\""#);
        assert_eq!(&source[layer.source_range(0..2)], "ab");
    }

    #[test]
    fn layers_stop_when_nothing_is_left_to_undo() {
        assert!(layers("plain text", 3).is_empty());
        assert!(layers(r"a \x b", 3).is_empty());
        let nested = layers(r"\\\/", 3);
        assert_eq!(nested.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), [r"\/", "/"]);
    }
}
