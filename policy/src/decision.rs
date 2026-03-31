//! Policy evaluation outcome — the result of checking an event against policy.

/// The outcome of evaluating an event against policy.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Display to user (no policy match, or explicit log match).
    Trace,
    /// Blocked by policy (returned -1/EACCES to caller).
    Block { rule: String, section: String },
    /// Allowed but flagged as warning.
    Warn { rule: String, section: String },
    /// Make target silently non-existent (NULL/ENOENT), don't display.
    Hide,
    /// Allowed by policy, don't display.
    Suppress,
}

impl Outcome {
    /// Whether the call should be allowed to proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Trace | Self::Warn { .. } | Self::Suppress)
    }

    /// Whether the event should be sent to the CLI for display.
    pub fn should_send(&self) -> bool {
        matches!(self, Self::Trace | Self::Block { .. } | Self::Warn { .. })
    }

    /// Whether this outcome blocks the call.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

/// Severity ranking for outcomes (higher = stricter).
pub fn severity(d: &Outcome) -> u8 {
    match d {
        Outcome::Trace => 0,
        Outcome::Suppress => 1,
        Outcome::Warn { .. } => 2,
        Outcome::Block { .. } => 3,
        Outcome::Hide => 4,
    }
}

/// Return the stricter of two outcomes.
pub fn pick_stricter(a: Outcome, b: Outcome) -> Outcome {
    if severity(&b) > severity(&a) {
        b
    } else {
        a
    }
}

/// Combine multiple outcomes, returning the strictest.
/// Returns `Trace` if the list is empty.
pub fn combine_outcomes(outcomes: Vec<Outcome>) -> Outcome {
    let mut result = Outcome::Trace;
    for d in outcomes {
        result = pick_stricter(result, d);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(severity(&Outcome::Trace) < severity(&Outcome::Suppress));
        assert!(
            severity(&Outcome::Suppress)
                < severity(&Outcome::Warn {
                    rule: String::new(),
                    section: String::new(),
                })
        );
        assert!(
            severity(&Outcome::Block {
                rule: String::new(),
                section: String::new(),
            }) < severity(&Outcome::Hide)
        );
    }

    #[test]
    fn test_pick_stricter() {
        let allow = Outcome::Suppress;
        let block = Outcome::Block {
            rule: "eval".into(),
            section: "functions".into(),
        };
        assert!(matches!(pick_stricter(allow, block), Outcome::Block { .. }));
    }

    #[test]
    fn test_combine_empty() {
        assert_eq!(combine_outcomes(vec![]), Outcome::Trace);
    }

    #[test]
    fn test_combine_picks_strictest() {
        let outcomes = vec![
            Outcome::Suppress,
            Outcome::Warn {
                rule: "x".into(),
                section: "s".into(),
            },
            Outcome::Trace,
        ];
        assert!(matches!(combine_outcomes(outcomes), Outcome::Warn { .. }));
    }
}
