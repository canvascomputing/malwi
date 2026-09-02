//! The registered types a `malicious` or an `exploitable` finding can carry,
//! and the follow-up each one opens. A type is a task and its schema, never an
//! edit to a role: everything it needs sits under the verdict that owns it,
//! beside the finding schema they all extend.

mod exploitable;
mod finding;
mod malicious;

pub(crate) use finding::{finding_schema_json, typed_schema};

use serde_json::Value;

/// The finding fields an investigation is handed, so it restates its parent
/// rather than opening a second finding on the same code.
const CARRIED_FIELDS: [&str; 6] = ["verdict", "type", "path", "line", "column", "description"];

/// A finding type and the follow-up that establishes or disproves it.
pub(crate) trait Type: Sync {
    /// The value stored in the finding's `type` field.
    fn name(&self) -> &'static str;

    /// The verdict this type belongs under, `malicious` or `exploitable`.
    fn verdict(&self) -> &'static str;

    /// One line telling the Analyst when to pick this name, bound into the
    /// finding schema's `type` description.
    fn summary(&self) -> &'static str;

    /// Reader-facing name for the behavior, without its internal type name.
    fn report_phrase(&self) -> &'static str;

    /// The investigation's task text.
    fn task(&self) -> &'static str;

    /// The properties this type adds to the finding.
    fn fields(&self) -> Value;

    /// What the investigation established, as one sentence for the Reporter.
    /// Called only once every field is present.
    fn render(&self, finding: &Value) -> String;

    /// The investigation's task body: the task, then the finding it is about.
    /// A field the investigation cannot see is one it would have to invent.
    fn body(&self, finding: &Value) -> String {
        let carried: serde_json::Map<String, Value> = CARRIED_FIELDS
            .iter()
            .filter(|name| !finding[**name].is_null())
            .map(|name| ((*name).to_string(), finding[*name].clone()))
            .collect();
        let carried = serde_json::to_string_pretty(&Value::Object(carried))
            .expect("a finding serializes as JSON");
        let block =
            format!("<finding_under_investigation>\n{carried}\n</finding_under_investigation>");
        self.task().trim().replace("{finding}", &block)
    }
}

/// The types malwi investigates. A finding without one opens nothing.
pub(crate) static TYPES: [&dyn Type; 3] = [
    &malicious::Obfuscation,
    &exploitable::SideLoading,
    &exploitable::Telemetry,
];

/// The registered type a value names.
pub(crate) fn find(name: &str) -> Option<&'static dyn Type> {
    TYPES.iter().copied().find(|entry| entry.name() == name)
}

/// Every registered value a finding's `type` may take.
pub(crate) fn type_values() -> Vec<&'static str> {
    TYPES.iter().map(|entry| entry.name()).collect()
}

/// The verdicts that may carry a registered type, in report order.
pub(crate) const TYPED_VERDICTS: [&str; 2] = ["malicious", "exploitable"];

/// One type's own field names, in schema order.
pub(crate) fn field_names(finding_type: &dyn Type) -> Vec<String> {
    finding_type
        .fields()
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default()
}

/// Every key a type can put on a finding, `type` included.
pub(crate) fn keys() -> Vec<String> {
    let mut keys = vec!["type".to_string()];
    for finding_type in TYPES {
        keys.extend(field_names(finding_type));
    }
    keys
}

/// The type a finding carries once an investigation established it.
pub(crate) fn established(finding: &Value) -> Option<&'static dyn Type> {
    let finding_type = find(finding["type"].as_str()?)?;
    field_names(finding_type)
        .iter()
        .all(|name| !finding[name].is_null())
        .then_some(finding_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The directory a type lives in is the verdict it answers.
    #[test]
    fn every_type_sits_under_its_verdict() {
        for verdict in TYPED_VERDICTS {
            let dir = format!("src/types/{verdict}");
            let filed: Vec<String> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{dir} is readable: {e}"))
                .flatten()
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rs"))
                .map(|entry| {
                    entry
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            let registered: Vec<String> = TYPES
                .iter()
                .filter(|finding_type| finding_type.verdict() == verdict)
                .map(|finding_type| finding_type.name().replace('-', "_"))
                .collect();
            for name in &registered {
                assert!(
                    filed.contains(name),
                    "{name} is registered {verdict} but not filed there"
                );
            }
            assert_eq!(
                filed.len(),
                registered.len(),
                "{verdict}: {filed:?} vs {registered:?}"
            );
        }
    }

    /// The README cards are the operator's view of what a verdict can extract.
    /// Every type and each field its focused pass adds must appear.
    #[test]
    fn the_readme_carries_every_type() {
        let readme = std::fs::read_to_string("../../README.md").expect("the README is readable");
        for finding_type in TYPES {
            let card = format!(
                "<code>{} / {}</code>",
                finding_type.verdict(),
                finding_type.name()
            );
            assert!(
                readme.contains(&card),
                "missing {} card",
                finding_type.name()
            );
            for field in field_names(finding_type) {
                assert!(
                    readme.contains(&format!("\"{field}\":")),
                    "{} card does not show `{field}`",
                    finding_type.name()
                );
            }
        }
    }

    /// The finding offers exactly the registered types.
    #[test]
    fn every_value_the_finding_offers_names_a_registered_type() {
        let values = type_values();
        assert_eq!(values.len(), TYPES.len());
        for name in values {
            assert!(find(name).is_some(), "{name}");
        }
        assert!(find("none").is_none());
    }

    #[test]
    fn type_names_are_unique() {
        let mut names: Vec<&str> = TYPES.iter().map(|entry| entry.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn report_phrases_are_plain_unique_language() {
        assert_eq!(
            find("obfuscation").unwrap().report_phrase(),
            "runtime execution of concealed code"
        );
        assert_eq!(
            find("side-loading").unwrap().report_phrase(),
            "execution of code fetched from an external source"
        );
        assert_eq!(
            find("telemetry").unwrap().report_phrase(),
            "external data transmission without affirmative opt-in"
        );
        let mut phrases: Vec<&str> = TYPES
            .iter()
            .map(|finding_type| {
                let phrase = finding_type.report_phrase();
                assert!(!phrase.trim().is_empty(), "{}", finding_type.name());
                assert!(
                    !phrase.contains(finding_type.name()),
                    "{}: {phrase}",
                    finding_type.name()
                );
                phrase
            })
            .collect();
        let before = phrases.len();
        phrases.sort_unstable();
        phrases.dedup();
        assert_eq!(phrases.len(), before);
    }

    /// A type is established only when its fields are present.
    #[test]
    fn a_type_without_its_fields_is_not_established() {
        let finding_type = find("side-loading").expect("side-loading is registered");
        assert!(established(&json!({"type": finding_type.name()})).is_none());
        assert!(established(&json!({})).is_none());

        let mut finding = json!({"type": finding_type.name()});
        for name in field_names(finding_type) {
            finding[name] = json!("filled");
        }
        assert!(established(&finding).is_some());
    }

    #[test]
    fn the_task_body_carries_the_finding_it_investigates() {
        let finding_type = find("side-loading").expect("side-loading is registered");
        let body = finding_type.body(&json!({
            "verdict": "exploitable", "type": finding_type.name(), "path": "a.py",
            "line": 3, "description": "x",
        }));
        assert!(!body.contains("{finding}"), "{body}");
        assert!(body.contains("<finding_under_investigation>"), "{body}");
        assert!(body.contains("\"path\": \"a.py\""), "{body}");
        assert!(
            body.contains(&format!("\"type\": \"{}\"", finding_type.name())),
            "{body}"
        );
        assert!(body.contains("\"line\": 3"), "{body}");
        assert!(body.contains("</finding_under_investigation>"), "{body}");
    }

    #[test]
    fn every_type_task_has_one_finding_slot() {
        for finding_type in TYPES {
            assert_eq!(
                finding_type.task().matches("{finding}").count(),
                1,
                "{}",
                finding_type.name()
            );
        }
    }

    #[test]
    fn every_type_task_uses_the_scoped_prompt_structure() {
        for finding_type in TYPES {
            let task = finding_type.task();
            crate::cli::assert_role_orientation(finding_type.name(), task);
            let context = task.find("## Context").expect("task has Context");
            let protocol = task
                .find("## Investigation Protocol")
                .expect("task has its protocol");
            let your_task = task.find("## Your Task").expect("task has Your Task");
            let trailer = task
                .rfind("\nCRITICAL:")
                .expect("task has a critical trailer");

            assert!(
                context < protocol && protocol < your_task && your_task < trailer,
                "{}",
                finding_type.name()
            );
        }
    }
}
