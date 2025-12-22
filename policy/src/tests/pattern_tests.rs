//! Tests for pattern matching.

use crate::pattern::{compile_pattern, compile_pattern_case_insensitive};

#[test]
fn test_exact_match() {
    let p = compile_pattern("eval").unwrap();
    assert!(p.matches("eval"));
    assert!(!p.matches("Eval"));
    assert!(!p.matches("evaluate"));
    assert!(!p.matches("myeval"));
    assert!(!p.matches(""));
}

#[test]
fn test_glob_star() {
    let p = compile_pattern("fs.*").unwrap();
    assert!(p.matches("fs.readFile"));
    assert!(p.matches("fs.writeFile"));
    assert!(p.matches("fs."));
    assert!(!p.matches("fs"));
    assert!(!p.matches("http.request"));
    assert!(!p.matches("myfs.read"));
}

#[test]
fn test_glob_star_prefix() {
    let p = compile_pattern("*.pypi.org").unwrap();
    assert!(p.matches("files.pypi.org"));
    assert!(p.matches("test.pypi.org"));
    assert!(!p.matches("pypi.org")); // Need something before .pypi.org
    assert!(!p.matches("files.pypi.org.evil.com"));
}

#[test]
fn test_glob_star_middle() {
    let p = compile_pattern("test.*.com").unwrap();
    assert!(p.matches("test.example.com"));
    assert!(p.matches("test.api.com"));
    assert!(!p.matches("test.com"));
    // For non-path patterns, * matches anything including dots
    assert!(p.matches("test.a.b.com"));
}

#[test]
fn test_glob_double_star() {
    let p = compile_pattern("/app/**/*.py").unwrap();
    assert!(p.matches("/app/main.py"));
    assert!(p.matches("/app/src/main.py"));
    assert!(p.matches("/app/src/lib/util.py"));
    assert!(!p.matches("/other/main.py"));
}

#[test]
fn test_glob_question_mark() {
    let p = compile_pattern("file?.txt").unwrap();
    assert!(p.matches("file1.txt"));
    assert!(p.matches("fileA.txt"));
    assert!(!p.matches("file12.txt"));
    assert!(!p.matches("file.txt"));
}

#[test]
fn test_glob_complex() {
    let p = compile_pattern("/app/*/test_*.py").unwrap();
    assert!(p.matches("/app/src/test_main.py"));
    assert!(p.matches("/app/lib/test_util.py"));
    assert!(!p.matches("/app/test_main.py")); // Need dir between app and test_
    assert!(!p.matches("/app/src/main.py")); // Doesn't start with test_
}

#[test]
fn test_regex_simple() {
    let p = compile_pattern("regex:^AWS_").unwrap();
    assert!(p.matches("AWS_ACCESS_KEY"));
    assert!(p.matches("AWS_SECRET"));
    assert!(!p.matches("MY_AWS_KEY"));
    assert!(!p.matches("aws_key")); // Case sensitive by default
}

#[test]
fn test_regex_complex() {
    let p = compile_pattern("regex:^(GET|POST|PUT|DELETE)$").unwrap();
    assert!(p.matches("GET"));
    assert!(p.matches("POST"));
    assert!(p.matches("DELETE"));
    assert!(!p.matches("PATCH"));
    assert!(!p.matches("get"));
    assert!(!p.matches("GET request"));
}

#[test]
fn test_regex_with_special_chars() {
    let p = compile_pattern("regex:.*\\.(onion|i2p)$").unwrap();
    assert!(p.matches("hidden.onion"));
    assert!(p.matches("site.i2p"));
    assert!(!p.matches("onion.com"));
}

#[test]
fn test_invalid_regex() {
    assert!(compile_pattern("regex:[invalid").is_err());
    assert!(compile_pattern("regex:(unclosed").is_err());
    assert!(compile_pattern("regex:*invalid").is_err());
}

#[test]
fn test_case_insensitive_exact() {
    let p = compile_pattern_case_insensitive("ONION").unwrap();
    assert!(p.matches_ignore_case("onion"));
    assert!(p.matches_ignore_case("ONION"));
    assert!(p.matches_ignore_case("Onion"));
}

#[test]
fn test_case_insensitive_glob() {
    let p = compile_pattern_case_insensitive("*.ONION").unwrap();
    assert!(p.matches("test.onion"));
    assert!(p.matches("TEST.ONION"));
    assert!(p.matches("Test.Onion"));
}

#[test]
fn test_case_insensitive_regex() {
    let p = compile_pattern_case_insensitive("regex:^AWS_").unwrap();
    assert!(p.matches("AWS_KEY"));
    assert!(p.matches("aws_key"));
    assert!(p.matches("Aws_Key"));
}

#[test]
fn test_endpoint_patterns() {
    // host:port matching
    let p1 = compile_pattern("127.0.0.1:*").unwrap();
    assert!(p1.matches("127.0.0.1:8080"));
    assert!(p1.matches("127.0.0.1:443"));
    assert!(p1.matches("127.0.0.1:22"));
    assert!(!p1.matches("192.168.1.1:8080"));

    let p2 = compile_pattern("*:443").unwrap();
    assert!(p2.matches("example.com:443"));
    assert!(p2.matches("localhost:443"));
    assert!(!p2.matches("example.com:80"));
    assert!(!p2.matches("example.com:4430"));

    let p3 = compile_pattern("*:22").unwrap();
    assert!(p3.matches("server.example.com:22"));
    assert!(!p3.matches("server.example.com:2222"));
}

#[test]
fn test_special_chars_escaped() {
    // Dots should be literal
    let p1 = compile_pattern("os.path.join").unwrap();
    assert!(p1.matches("os.path.join"));
    assert!(!p1.matches("os_path_join"));
    assert!(!p1.matches("osXpathXjoin"));

    // Other regex metacharacters should be escaped
    let p2 = compile_pattern("func(a,b)").unwrap();
    assert!(p2.matches("func(a,b)"));
    assert!(!p2.matches("funcab"));

    let p3 = compile_pattern("$HOME").unwrap();
    assert!(p3.matches("$HOME"));
    assert!(!p3.matches("HOME"));

    let p4 = compile_pattern("[test]").unwrap();
    assert!(p4.matches("[test]"));
    assert!(!p4.matches("test"));
    assert!(!p4.matches("t"));
}

#[test]
fn test_empty_pattern() {
    let p = compile_pattern("").unwrap();
    assert!(p.matches(""));
    assert!(!p.matches("anything"));
}

#[test]
fn test_star_only() {
    let p = compile_pattern("*").unwrap();
    assert!(p.matches("anything"));
    assert!(p.matches(""));
    assert!(p.matches("multi.part.name"));
    // For non-path patterns (doesn't start with / or ~), * matches everything
    assert!(p.matches("path/to/file"));
}

#[test]
fn test_double_star_only() {
    let p = compile_pattern("**").unwrap();
    assert!(p.matches("anything"));
    assert!(p.matches("path/to/file"));
    assert!(p.matches(""));
}

#[test]
fn test_pattern_original() {
    let p = compile_pattern("fs.*").unwrap();
    assert_eq!(p.original(), "fs.*");

    let p = compile_pattern("regex:^test").unwrap();
    assert_eq!(p.original(), "regex:^test");

    let p = compile_pattern("exact").unwrap();
    assert_eq!(p.original(), "exact");
}
