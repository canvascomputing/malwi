//! Minimal YAML parser for policy files.
//!
//! Supports the subset of YAML needed for malwi policy files:
//! key-value pairs, nested maps, block/flow sequences, quoted/unquoted strings,
//! integers, comments, and flow maps in sequences.

use std::fmt;

/// A parsed YAML value.
#[derive(Debug, Clone, PartialEq)]
pub enum YamlValue {
    String(String),
    Integer(i64),
    Sequence(Vec<YamlValue>),
    Mapping(Vec<(String, YamlValue)>),
}

/// Error from YAML parsing.
#[derive(Debug, Clone)]
pub struct YamlError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for YamlError {}

/// Parse a YAML string into a `YamlValue`.
pub fn parse(input: &str) -> Result<YamlValue, YamlError> {
    let lines = preprocess(input);
    if lines.is_empty() {
        return Ok(YamlValue::Mapping(Vec::new()));
    }
    let mut pos = 0;
    parse_value(&lines, &mut pos, 0)
}

/// A preprocessed line with its original line number, indentation level, and content.
#[derive(Debug)]
struct Line {
    number: usize,
    indent: usize,
    content: String,
}

/// Strip comments and blank lines, track indentation.
fn preprocess(input: &str) -> Vec<Line> {
    let mut lines = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let content = strip_comment(raw);
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = content.len() - content.trim_start().len();
        lines.push(Line {
            number: i + 1,
            indent,
            content: trimmed.to_string(),
        });
    }
    lines
}

/// Strip a `#` comment from a line, respecting quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Parse a value starting at `pos` with the given minimum indentation.
fn parse_value(lines: &[Line], pos: &mut usize, min_indent: usize) -> Result<YamlValue, YamlError> {
    if *pos >= lines.len() {
        return Ok(YamlValue::Mapping(Vec::new()));
    }

    let line = &lines[*pos];
    if line.content.starts_with("- ") || line.content == "-" {
        parse_block_sequence(lines, pos, line.indent)
    } else if line.content.contains(": ") || line.content.ends_with(':') {
        parse_block_mapping(lines, pos, min_indent)
    } else {
        // Bare scalar at top level
        let val = parse_scalar(&line.content, line.number)?;
        *pos += 1;
        Ok(val)
    }
}

/// Parse a block mapping (key: value pairs at the same indentation).
fn parse_block_mapping(
    lines: &[Line],
    pos: &mut usize,
    _min_indent: usize,
) -> Result<YamlValue, YamlError> {
    let mut pairs = Vec::new();
    let map_indent = lines[*pos].indent;

    while *pos < lines.len() {
        let line = &lines[*pos];
        // Stop if we've dedented past the mapping level
        if line.indent < map_indent {
            break;
        }
        // Skip lines at deeper indentation (consumed by child parsers)
        if line.indent > map_indent {
            break;
        }

        // Must be a key: line
        let (key, inline_value) = split_key_value(&line.content, line.number)?;
        let line_number = line.number;
        *pos += 1;

        let value = if let Some(inline) = inline_value {
            let trimmed = inline.trim();
            if trimmed.starts_with('[') {
                parse_flow_sequence(trimmed, line_number)?
            } else {
                parse_scalar(trimmed, line_number)?
            }
        } else {
            // Block child — value is on subsequent indented lines
            if *pos < lines.len() && lines[*pos].indent > map_indent {
                parse_value(lines, pos, lines[*pos].indent)?
            } else {
                // key: with nothing following — treat as empty string
                YamlValue::String(String::new())
            }
        };

        pairs.push((key, value));
    }

    Ok(YamlValue::Mapping(pairs))
}

/// Parse a block sequence (lines starting with `- ` at the same indentation).
fn parse_block_sequence(
    lines: &[Line],
    pos: &mut usize,
    seq_indent: usize,
) -> Result<YamlValue, YamlError> {
    let mut items = Vec::new();

    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < seq_indent {
            break;
        }
        if line.indent != seq_indent {
            break;
        }
        if !line.content.starts_with("- ") && line.content != "-" {
            break;
        }

        let after_dash = if line.content == "-" {
            ""
        } else {
            &line.content[2..]
        };
        let trimmed = after_dash.trim();
        let line_number = line.number;

        if trimmed.is_empty() {
            // `- ` followed by indented block on next lines
            *pos += 1;
            if *pos < lines.len() && lines[*pos].indent > seq_indent {
                let child = parse_value(lines, pos, lines[*pos].indent)?;
                items.push(child);
            } else {
                items.push(YamlValue::String(String::new()));
            }
        } else if trimmed.starts_with('[') {
            // `- [a, b, c]`  (flow sequence as list item)
            items.push(parse_flow_sequence(trimmed, line_number)?);
            *pos += 1;
        } else if let Some((key, val_part)) = try_split_key_value(trimmed) {
            // `- "key": [constraints]`  or  `- key: value`
            let val = if let Some(v) = val_part {
                let v = v.trim();
                if v.starts_with('[') {
                    parse_flow_sequence(v, line_number)?
                } else {
                    parse_scalar(v, line_number)?
                }
            } else {
                // `- key:` followed by indented block
                *pos += 1;
                if *pos < lines.len() && lines[*pos].indent > seq_indent {
                    parse_value(lines, pos, lines[*pos].indent)?
                } else {
                    YamlValue::String(String::new())
                }
            };
            items.push(YamlValue::Mapping(vec![(key, val)]));
            if val_part.is_some() {
                *pos += 1;
            }
        } else {
            // Simple scalar item
            items.push(parse_scalar(trimmed, line_number)?);
            *pos += 1;
        }
    }

    Ok(YamlValue::Sequence(items))
}

/// Parse a flow sequence like `[a, b, c]`.
fn parse_flow_sequence(s: &str, line: usize) -> Result<YamlValue, YamlError> {
    let s = s.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(YamlError {
            line,
            message: format!("expected flow sequence [...], got: {}", s),
        });
    }
    let inner = &s[1..s.len() - 1];
    if inner.trim().is_empty() {
        return Ok(YamlValue::Sequence(Vec::new()));
    }

    let parts = split_flow_items(inner);
    let mut items = Vec::new();
    for part in parts {
        let trimmed = part.trim();
        items.push(parse_scalar(trimmed, line)?);
    }
    Ok(YamlValue::Sequence(items))
}

/// Split flow sequence items by commas, respecting quotes.
fn split_flow_items(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();

    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b',' if !in_single && !in_double => {
                items.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&s[start..]);
    items
}

/// Split a line into key and optional inline value.
/// Returns `(key, Some(value))` for `key: value` or `(key, None)` for `key:`.
fn split_key_value(line: &str, line_num: usize) -> Result<(String, Option<&str>), YamlError> {
    match try_split_key_value(line) {
        Some((key, val)) => Ok((key, val)),
        None => Err(YamlError {
            line: line_num,
            message: format!("expected 'key: value' or 'key:', got: {}", line),
        }),
    }
}

/// Try to split a line into key and optional value. Returns None if not a key-value line.
fn try_split_key_value(line: &str) -> Option<(String, Option<&str>)> {
    // Find the colon that separates key from value, skipping colons inside quotes
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;

    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                // Must be followed by space, end of string, or be at the end
                if i + 1 == bytes.len() || bytes[i + 1] == b' ' {
                    let key_raw = &line[..i];
                    let key = unquote(key_raw.trim());
                    let rest = if i + 1 < bytes.len() {
                        let after = &line[i + 2..]; // skip ": "
                        let trimmed = after.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(after)
                        }
                    } else {
                        None
                    };
                    return Some((key, rest));
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a scalar value (string or integer).
fn parse_scalar(s: &str, _line: usize) -> Result<YamlValue, YamlError> {
    let s = s.trim();

    // Quoted strings
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return Ok(YamlValue::String(s[1..s.len() - 1].to_string()));
    }

    // Try integer
    if let Ok(n) = s.parse::<i64>() {
        return Ok(YamlValue::Integer(n));
    }

    // Unquoted string
    Ok(YamlValue::String(s.to_string()))
}

/// Remove surrounding quotes from a string if present.
fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_key_value() {
        let v = parse("version: 1\n").unwrap();
        assert_eq!(
            v,
            YamlValue::Mapping(vec![("version".into(), YamlValue::Integer(1))])
        );
    }

    #[test]
    fn test_nested_mapping() {
        let yaml = "python:\n  deny:\n    - eval\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(pairs[0].0, "python");
            if let YamlValue::Mapping(inner) = &pairs[0].1 {
                assert_eq!(inner[0].0, "deny");
                if let YamlValue::Sequence(items) = &inner[0].1 {
                    assert_eq!(items[0], YamlValue::String("eval".into()));
                } else {
                    panic!("expected sequence");
                }
            } else {
                panic!("expected mapping");
            }
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_flow_sequence() {
        let yaml = "protocols: [tcp, https, http]\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            if let YamlValue::Sequence(items) = &pairs[0].1 {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], YamlValue::String("tcp".into()));
                assert_eq!(items[1], YamlValue::String("https".into()));
                assert_eq!(items[2], YamlValue::String("http".into()));
            } else {
                panic!("expected sequence");
            }
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_quoted_strings() {
        let yaml = "key: \"hello world\"\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(pairs[0].1, YamlValue::String("hello world".into()));
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_comments() {
        let yaml = "# comment\nversion: 1 # inline\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(pairs[0].0, "version");
            assert_eq!(pairs[0].1, YamlValue::Integer(1));
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_sequence_with_map() {
        let yaml = "items:\n  - \"key\": [a, b]\n  - plain\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            if let YamlValue::Sequence(items) = &pairs[0].1 {
                assert_eq!(items.len(), 2);
                // First item is a mapping
                if let YamlValue::Mapping(m) = &items[0] {
                    assert_eq!(m[0].0, "key");
                    if let YamlValue::Sequence(vals) = &m[0].1 {
                        assert_eq!(vals.len(), 2);
                    } else {
                        panic!("expected sequence value");
                    }
                } else {
                    panic!("expected mapping item");
                }
                // Second item is a string
                assert_eq!(items[1], YamlValue::String("plain".into()));
            } else {
                panic!("expected sequence");
            }
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_empty_flow_sequence() {
        let yaml = "items: []\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(pairs[0].1, YamlValue::Sequence(Vec::new()));
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_empty_input() {
        let v = parse("").unwrap();
        assert_eq!(v, YamlValue::Mapping(Vec::new()));
    }

    #[test]
    fn test_comment_in_quoted_string() {
        let yaml = "key: \"value # not a comment\"\n";
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(
                pairs[0].1,
                YamlValue::String("value # not a comment".into())
            );
        } else {
            panic!("expected mapping");
        }
    }

    #[test]
    fn test_policy_format() {
        let yaml = r#"
version: 1
python:
  allow:
    - json.loads
    - "requests.*": ["https://api.example.com/*"]
  deny:
    - eval
network:
  protocols: [tcp, https]
  deny:
    - "*.onion"
"#;
        let v = parse(yaml).unwrap();
        if let YamlValue::Mapping(pairs) = &v {
            assert_eq!(pairs.len(), 3);
            assert_eq!(pairs[0].0, "version");
            assert_eq!(pairs[1].0, "python");
            assert_eq!(pairs[2].0, "network");
        } else {
            panic!("expected mapping");
        }
    }
}
