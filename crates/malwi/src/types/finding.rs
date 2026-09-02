//! The finding every analysis task returns, and the document one type's
//! investigation is held to. The base sits here rather than in `report.rs`
//! because a type extends it.

use agentwerk::schemas::Schema;
use serde_json::{json, Value};

use super::{field_names, type_values, Type, TYPED_VERDICTS, TYPES};

/// The Analyst finding, as a plain JSON document.
///
/// `type` is optional: its presence opens a focused investigation, while its
/// absence means no registered type applies. Each registered type implies its
/// owning verdict, so a benign finding cannot carry one.
pub(crate) fn finding_schema_json() -> Value {
    json!({
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["malicious", "exploitable", "benign"], "description": "The decision established by the supplied evidence."},
            "path": {"type": "string", "minLength": 1, "description": "Path of the decisive code, relative to the scanned tree."},
            "line": {"type": "integer", "description": "Line of the decisive code when established."},
            "column": {"type": "integer", "description": "Column of the decisive code when established."},
            "description": {"type": "string", "minLength": 1, "description": "A concise evidence-grounded explanation of the decision and its exposure."},
            "type": {
                "type": "string",
                "enum": type_values(),
                "description": type_description(),
            },
        },
        "required": ["verdict", "path", "description"],
        "allOf": type_conditionals(),
    })
}

/// One conditional per registered type, binding it to its owning verdict.
fn type_conditionals() -> Vec<Value> {
    TYPES
        .iter()
        .map(|finding_type| {
            json!({
                "if": {
                    "properties": {"type": {"const": finding_type.name()}},
                    "required": ["type"],
                },
                "then": {"properties": {"verdict": {"const": finding_type.verdict()}}},
            })
        })
        .collect()
}

/// What the Analyst reads to choose a `type`, assembled from the registry. The
/// schema is serialized into the `finish` tool, so this is where the types are
/// taught.
fn type_description() -> String {
    let listed: String = TYPED_VERDICTS
        .iter()
        .map(|verdict| {
            let names: String = TYPES
                .iter()
                .filter(|finding_type| finding_type.verdict() == *verdict)
                .map(|finding_type| {
                    format!(
                        "  \"{}\": {}\n",
                        finding_type.name(),
                        finding_type.summary()
                    )
                })
                .collect();
            format!("On a {verdict} finding:\n{names}")
        })
        .collect();
    format!(
        "An optional registered behavior supported by this finding. Include exactly one listed \
         type only when the evidence matches it. Otherwise omit this field. Benign findings cannot \
         carry a type.\n\n{listed}",
    )
}

/// One type's document, compiled. An investigation carries it on the task
/// rather than through a label, since the label is what gets the task claimed
/// by an Analyst.
pub(crate) fn typed_schema(finding_type: &dyn Type) -> Schema {
    Schema::new(typed_schema_json(finding_type)).expect("a type's finding schema is valid")
}

/// Finding schema for one type's investigation: the base finding plus the
/// fields that type needs, required only once `type` names it. Built from the
/// base document, so a field added to the finding reaches every
/// investigation without a second edit.
pub(crate) fn typed_schema_json(finding_type: &dyn Type) -> Value {
    let mut document = finding_schema_json();
    let required = field_names(finding_type);
    let properties = document["properties"]
        .as_object_mut()
        .expect("analyst schema declares properties");
    properties["type"]["enum"] = json!([finding_type.name()]);
    properties["type"]["description"] = json!(format!(
        "Keep \"{name}\" only when the evidence establishes it, then provide {fields}. Omit \
         this field when the evidence rules it out.",
        name = finding_type.name(),
        fields = required.join(", "),
    ));
    if let Some(fields) = finding_type.fields().as_object() {
        for (name, definition) in fields {
            properties.insert(name.clone(), definition.clone());
        }
    }
    document["allOf"]
        .as_array_mut()
        .expect("the base document carries type conditionals")
        .push(json!({
            "if": {"properties": {"type": {"const": finding_type.name()}}, "required": ["type"]},
            "then": {"required": required},
        }));
    document
}

#[cfg(test)]
mod tests {
    use super::super::find;
    use super::*;

    /// The finding document compiled for validation.
    fn finding_schema() -> Schema {
        Schema::new(finding_schema_json()).expect("finding schema is a valid document")
    }

    /// The finding an investigation returns once it established its type.
    fn side_loading_finding() -> Value {
        json!({
            "verdict": "exploitable",
            "path": "scripts/install.js",
            "line": 12,
            "description": "downloads and runs a setup script",
            "type": "side-loading",
            "source": "https://cdn.example.test/setup.sh",
            "control": "static",
            "user_consent": false,
            "trigger": {
                "phase": "installation",
                "location": {"path": "package.json", "line": 4},
                "execution_condition": "always, on every install",
            },
        })
    }

    fn telemetry_finding() -> Value {
        json!({
            "verdict": "exploitable",
            "path": "src/telemetry.py",
            "line": 18,
            "description": "sends usage data at startup without opt-in",
            "type": "telemetry",
            "provider": "Segment",
            "destination": "https://api.segment.io/v1/track at src/telemetry.py:18",
            "data": ["hostname from platform.node() at src/telemetry.py:12"],
            "user_consent": false,
            "trigger": {
                "phase": "startup",
                "location": {"path": "src/telemetry.py", "line": 18},
                "execution_condition": "whenever the module is imported",
                "cadence": "once per process start",
            },
        })
    }

    #[test]
    fn a_typed_schema_requires_its_fields_once_the_finding_names_the_type() {
        let schema = Schema::new(typed_schema_json(
            find("side-loading").expect("side-loading is registered"),
        ))
        .expect("a valid document");
        // Naming the type without establishing it is rejected.
        assert!(schema
            .validate(json!({
                "verdict": "exploitable", "path": "a.js", "description": "x",
                "type": "side-loading",
            }))
            .is_err());
        // A name outside the narrowed enum is not a second spelling of the type.
        assert!(schema
            .validate(json!({
                "verdict": "exploitable", "path": "a.js", "description": "x",
                "type": "sideloading",
            }))
            .is_err());
        assert!(schema.validate(side_loading_finding()).is_ok());
    }

    /// An investigation rules its proposed type out by omitting `type`.
    #[test]
    fn a_typed_schema_accepts_a_finding_without_a_type() {
        let schema = Schema::new(typed_schema_json(
            find("side-loading").expect("side-loading is registered"),
        ))
        .expect("a valid document");
        assert!(schema
            .validate(json!({
                "verdict": "exploitable", "path": "a.js", "line": 12,
                "description": "the fetched file is checked into the repository",
            }))
            .is_ok());
        assert!(schema
            .validate(json!({
                "verdict": "exploitable", "path": "a.js", "line": 12, "type": "none",
                "description": "the fetched file is checked into the repository",
            }))
            .is_err());
    }

    #[test]
    fn a_side_loading_trigger_needs_a_phase_a_location_and_a_condition() {
        let schema = Schema::new(typed_schema_json(
            find("side-loading").expect("side-loading is registered"),
        ))
        .expect("a valid document");
        for trigger in [
            json!({"phase": "installation", "location": {"path": "package.json"}}),
            json!({"phase": "installation", "location": {"line": 4},
                   "execution_condition": "always"}),
            json!({"location": {"path": "package.json"}, "execution_condition": "always"}),
        ] {
            let mut finding = side_loading_finding();
            finding["trigger"] = trigger.clone();
            assert!(schema.validate(finding).is_err(), "{trigger}");
        }
    }

    #[test]
    fn a_telemetry_schema_requires_every_transmission_field() {
        let finding_type = find("telemetry").expect("telemetry is registered");
        let schema = Schema::new(typed_schema_json(finding_type)).expect("a valid document");
        assert!(schema.validate(telemetry_finding()).is_ok());

        for field in ["provider", "destination", "data", "user_consent", "trigger"] {
            let mut finding = telemetry_finding();
            finding.as_object_mut().unwrap().remove(field);
            assert!(schema.validate(finding).is_err(), "missing {field}");
        }
    }

    #[test]
    fn telemetry_data_must_name_at_least_one_nonempty_value() {
        let finding_type = find("telemetry").expect("telemetry is registered");
        let schema = Schema::new(typed_schema_json(finding_type)).expect("a valid document");
        for data in [json!([]), json!([""])] {
            let mut finding = telemetry_finding();
            finding["data"] = data.clone();
            assert!(schema.validate(finding).is_err(), "{data}");
        }
    }

    #[test]
    fn telemetry_trigger_needs_a_supported_phase_location_condition_and_cadence() {
        let finding_type = find("telemetry").expect("telemetry is registered");
        let schema = Schema::new(typed_schema_json(finding_type)).expect("a valid document");
        for trigger in [
            json!({"phase": "startup", "location": {"path": "a.py"}, "execution_condition": "always"}),
            json!({"phase": "startup", "location": {"path": "a.py"}, "cadence": "once"}),
            json!({"phase": "startup", "location": {"line": 4}, "execution_condition": "always", "cadence": "once"}),
            json!({"phase": "shutdown", "location": {"path": "a.py"}, "execution_condition": "always", "cadence": "once"}),
        ] {
            let mut finding = telemetry_finding();
            finding["trigger"] = trigger.clone();
            assert!(schema.validate(finding).is_err(), "{trigger}");
        }
    }

    #[test]
    fn the_finding_schema_requires_a_well_formed_verdict() {
        let schema = finding_schema();
        assert!(schema.validate(json!({"description": "x"})).is_err());
        assert!(schema
            .validate(json!({"verdict": "sketchy", "path": "a.py", "description": "x"}))
            .is_err());
        assert!(schema
            .validate(json!({
                "verdict": "malicious", "path": "a.py", "line": 3, "column": 1,
                "type": "obfuscation", "description": "decode-then-exec backdoor",
            }))
            .is_ok());
    }

    #[test]
    fn a_type_is_optional_and_none_is_not_a_type() {
        let schema = finding_schema();
        let finding =
            |verdict: &str| json!({"verdict": verdict, "path": "a.py", "description": "x"});

        assert!(schema.validate(finding("malicious")).is_ok());
        assert!(schema.validate(finding("exploitable")).is_ok());
        assert!(schema.validate(finding("benign")).is_ok());

        for verdict in TYPED_VERDICTS {
            let mut unregistered = finding(verdict);
            unregistered["type"] = json!("a-name-nobody-registered");
            assert!(schema.validate(unregistered).is_err(), "{verdict}");

            let mut none = finding(verdict);
            none["type"] = json!("none");
            assert!(schema.validate(none).is_err(), "{verdict}");
        }
    }

    /// A finding may name only a type owned by its verdict.
    #[test]
    fn a_finding_cannot_name_a_type_from_another_verdict() {
        let schema = finding_schema();
        let finding = |verdict: &str, kind: &str| json!({"verdict": verdict, "path": "a.py", "description": "x", "type": kind});

        assert!(schema
            .validate(finding("exploitable", "side-loading"))
            .is_ok());
        assert!(schema.validate(finding("exploitable", "telemetry")).is_ok());
        assert!(schema.validate(finding("malicious", "obfuscation")).is_ok());
        assert!(schema
            .validate(finding("malicious", "side-loading"))
            .is_err());
        assert!(schema.validate(finding("malicious", "telemetry")).is_err());
        assert!(schema
            .validate(finding("exploitable", "obfuscation"))
            .is_err());

        assert!(schema.validate(finding("benign", "side-loading")).is_err());
    }
}
