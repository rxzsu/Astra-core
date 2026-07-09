use std::io::{self, Read};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Content,
    Escape,
    DoubleQuote,
    DoubleQuoteEscape,
    SingleQuote,
    SingleQuoteEscape,
    Comment,
    Slash,
    MultilineComment,
    MultilineCommentStar,
}

pub struct JsonCommentReader<R: Read> {
    inner: io::BufReader<R>,
    state: State,
}

impl<R: Read> JsonCommentReader<R> {
    pub fn new(reader: R) -> Self {
        JsonCommentReader {
            inner: io::BufReader::new(reader),
            state: State::Content,
        }
    }
}

impl<R: Read> Read for JsonCommentReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        let mut pending: Option<u8> = None;

        while written < buf.len() {
            if let Some(b) = pending.take() {
                buf[written] = b;
                written += 1;
                if written >= buf.len() {
                    break;
                }
            }

            let mut byte = [0u8; 1];
            let n = self.inner.read(&mut byte)?;
            if n == 0 {
                break;
            }
            let x = byte[0];

            match self.state {
                State::Content => match x {
                    b'"' => {
                        self.state = State::DoubleQuote;
                        buf[written] = x;
                        written += 1;
                    }
                    b'\'' => {
                        self.state = State::SingleQuote;
                        buf[written] = x;
                        written += 1;
                    }
                    b'\\' => {
                        self.state = State::Escape;
                    }
                    b'#' => {
                        self.state = State::Comment;
                    }
                    b'/' => {
                        self.state = State::Slash;
                    }
                    _ => {
                        buf[written] = x;
                        written += 1;
                    }
                },
                State::Escape => {
                    // Write both bytes
                    buf[written] = b'\\';
                    written += 1;
                    if written < buf.len() {
                        buf[written] = x;
                        written += 1;
                    }
                    self.state = State::Content;
                }
                State::DoubleQuote => match x {
                    b'"' => {
                        self.state = State::Content;
                        buf[written] = x;
                        written += 1;
                    }
                    b'\\' => {
                        self.state = State::DoubleQuoteEscape;
                        buf[written] = x;
                        written += 1;
                    }
                    _ => {
                        buf[written] = x;
                        written += 1;
                    }
                },
                State::DoubleQuoteEscape => {
                    buf[written] = b'\\';
                    written += 1;
                    if written < buf.len() {
                        buf[written] = x;
                        written += 1;
                    }
                    self.state = State::DoubleQuote;
                }
                State::SingleQuote => match x {
                    b'\'' => {
                        self.state = State::Content;
                        buf[written] = x;
                        written += 1;
                    }
                    b'\\' => {
                        self.state = State::SingleQuoteEscape;
                        buf[written] = x;
                        written += 1;
                    }
                    _ => {
                        buf[written] = x;
                        written += 1;
                    }
                },
                State::SingleQuoteEscape => {
                    buf[written] = b'\\';
                    written += 1;
                    if written < buf.len() {
                        buf[written] = x;
                        written += 1;
                    }
                    self.state = State::SingleQuote;
                }
                State::Comment => {
                    if x == b'\n' {
                        self.state = State::Content;
                        buf[written] = b'\n';
                        written += 1;
                    }
                }
                State::Slash => match x {
                    b'/' => {
                        self.state = State::Comment;
                    }
                    b'*' => {
                        self.state = State::MultilineComment;
                    }
                    _ => {
                        // Not a comment: emit '/' and the current byte
                        buf[written] = b'/';
                        written += 1;
                        if written < buf.len() {
                            buf[written] = x;
                            written += 1;
                        }
                    }
                },
                State::MultilineComment => match x {
                    b'*' => {
                        self.state = State::MultilineCommentStar;
                    }
                    b'\n' => {
                        buf[written] = b'\n';
                        written += 1;
                    }
                    _ => {}
                },
                State::MultilineCommentStar => match x {
                    b'/' => {
                        self.state = State::Content;
                    }
                    b'*' => {}
                    b'\n' => {
                        buf[written] = b'\n';
                        written += 1;
                    }
                    _ => {
                        self.state = State::MultilineComment;
                    }
                },
            }
        }
        if written == 0 {
            return Ok(0);
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(s: &str) -> String {
        let mut reader = JsonCommentReader::new(s.as_bytes());
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn test_single_line_slash() {
        assert_eq!(strip("hello // world\n"), "hello \n");
    }

    #[test]
    fn test_multi_line_comment() {
        assert_eq!(strip("a /* comment */ b"), "a  b");
    }

    #[test]
    fn test_python_comment() {
        assert_eq!(strip("a # comment\nb"), "a \nb");
    }

    #[test]
    fn test_string_preserved() {
        assert_eq!(
            strip(r#"{"key": "value // not comment"}"#),
            r#"{"key": "value // not comment"}"#
        );
    }

    #[test]
    fn test_not_slash() {
        assert_eq!(strip("a/b"), "a/b");
    }

    #[test]
    fn test_newlines_preserved_in_block() {
        let result = strip("/*\nline1\nline2\n*/x");
        assert_eq!(result, "\n\n\nx");
    }
}
