//! Obfuscation: code the tree carries in an encoded or obfuscated form,
//! turned back into code or bytes at run time and executed.

use serde_json::{json, Value};

use super::super::Type;

/// The follow-up an Analyst opens for an `obfuscation` finding.
pub(crate) struct Obfuscation;

const TASK: &str = include_str!("obfuscation.md");

impl Type for Obfuscation {
    fn name(&self) -> &'static str {
        "obfuscation"
    }

    fn verdict(&self) -> &'static str {
        "malicious"
    }

    fn summary(&self) -> &'static str {
        "a value the tree carries encoded or obfuscated, turned back into code or bytes at run \
         time and then executed."
    }

    fn report_phrase(&self) -> &'static str {
        "runtime execution of concealed code"
    }

    fn task(&self) -> &'static str {
        TASK
    }

    fn fields(&self) -> Value {
        json!({
            "payload": {
                "type": "string",
                "minLength": 1,
                "description": "The encoded or concealed value quoted from the tree, truncated only when long, with its file and line.",
            },
            "transform": {
                "type": "string",
                "minLength": 1,
                "description": "The exact decode or deobfuscation operation, including stacked transforms, with its file and line.",
            },
            "sink": {
                "type": "string",
                "minLength": 1,
                "description": "The execution sink reached by the decoded value, with its file and line. A parser alone is not an execution sink.",
            },
            "trigger": {
                "type": "object",
                "properties": {
                    "phase": {
                        "type": "string",
                        "enum": ["installation", "runtime"],
                        "description": "Use \"installation\" for build or install execution. Use \"runtime\" for import-time or later execution.",
                    },
                    "location": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "minLength": 1, "description": "Path of the code that initiates decoding, relative to the scanned tree."},
                            "line": {"type": "integer", "description": "Line of the trigger when established."},
                            "column": {"type": "integer", "description": "Column of the trigger when established."},
                        },
                        "required": ["path"],
                        "description": "The trigger site, which may differ from the decode and sink sites.",
                    },
                    "execution_condition": {
                        "type": "string",
                        "minLength": 1,
                        "description": "The code condition that causes decoding, such as every install, import, or a named environment check.",
                    },
                },
                "required": ["phase", "location", "execution_condition"],
                "description": "When, where, and under what condition decoding and execution begin.",
            },
        })
    }

    /// Prose rather than a key/value block, which `reporter.md` cuts as
    /// vocabulary of the review.
    fn render(&self, finding: &Value) -> String {
        let payload = finding["payload"].as_str().unwrap_or("an encoded value");
        let mut out = format!("This code carries {payload}");
        if let Some(transform) = finding["transform"].as_str() {
            out.push_str(&format!(", turns it back with {transform}"));
        }
        if let Some(sink) = finding["sink"].as_str() {
            out.push_str(&format!(", and executes the result at {sink}"));
        }
        out.push('.');
        let trigger = &finding["trigger"];
        if let Some(path) = trigger["location"]["path"].as_str() {
            let line = trigger["location"]["line"]
                .as_u64()
                .map(|n| format!(":{n}"))
                .unwrap_or_default();
            out.push_str(&format!(" The decode fires at {path}{line}"));
            match trigger["phase"].as_str() {
                Some("installation") => out.push_str(", during installation"),
                Some("runtime") => out.push_str(", at run time"),
                _ => {}
            }
            if let Some(condition) = trigger["execution_condition"].as_str() {
                out.push_str(&format!(", {condition}"));
            }
            out.push('.');
        }
        out.push('\n');
        out
    }
}
