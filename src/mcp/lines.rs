use std::io::{self, BufRead, Read};

pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

pub enum Line {
    Text(String),
    NotUtf8,
    TooLong,
}

pub fn read_line(input: &mut impl BufRead) -> io::Result<Option<Line>> {
    let mut bytes = Vec::new();
    let read = input
        .by_ref()
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    } else if bytes.len() > MAX_MESSAGE_BYTES {
        skip_line(input)?;
        return Ok(Some(Line::TooLong));
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(Some(String::from_utf8(bytes).map_or(Line::NotUtf8, Line::Text)))
}

fn skip_line(input: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        if let Some(at) = buffer.iter().position(|byte| *byte == b'\n') {
            input.consume(at + 1);
            return Ok(());
        }
        let len = buffer.len();
        input.consume(len);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn lines(input: Vec<u8>) -> Vec<String> {
        let mut input = Cursor::new(input);
        std::iter::from_fn(|| read_line(&mut input).unwrap())
            .map(|line| match line {
                Line::Text(text) => text,
                Line::NotUtf8 => "<not utf-8>".to_string(),
                Line::TooLong => "<too long>".to_string(),
            })
            .collect()
    }

    #[test]
    fn lines_lose_their_endings() {
        assert_eq!(lines(b"a\nb\r\n\nlast".to_vec()), ["a", "b", "", "last"]);
    }

    #[test]
    fn bad_lines_are_reported_and_reading_goes_on() {
        let long = vec![b'x'; MAX_MESSAGE_BYTES + 10];
        let input = [b"ok\n".as_slice(), &long, b"\n\xff\nnext\n"].concat();
        assert_eq!(lines(input), ["ok", "<too long>", "<not utf-8>", "next"]);
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_fine() {
        let input = [vec![b'x'; MAX_MESSAGE_BYTES], b"\n".to_vec()].concat();
        assert_eq!(lines(input)[0].len(), MAX_MESSAGE_BYTES);
    }
}
