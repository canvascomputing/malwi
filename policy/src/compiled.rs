use std::collections::HashMap;

use crate::pattern::CompiledPattern;

/// A fully compiled policy ready for evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    pub version: u32,
    pub sections: HashMap<SectionKey, CompiledSection>,
}

impl CompiledPolicy {
    /// Get a section by runtime and category.
    pub fn get_section(&self, key: &SectionKey) -> Option<&CompiledSection> {
        self.sections.get(key)
    }

    /// Check if a section exists.
    pub fn has_section(&self, key: &SectionKey) -> bool {
        self.sections.contains_key(key)
    }

    /// Iterate over all sections in the policy.
    pub fn iter_sections(&self) -> impl Iterator<Item = (&SectionKey, &CompiledSection)> {
        self.sections.iter()
    }
}

/// Key for looking up a compiled section.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SectionKey {
    pub runtime: Option<Runtime>,
    pub category: Category,
}

impl SectionKey {
    pub fn new(runtime: Option<Runtime>, category: Category) -> Self {
        Self { runtime, category }
    }

    pub fn global(category: Category) -> Self {
        Self {
            runtime: None,
            category,
        }
    }

    pub fn for_runtime(runtime: Runtime, category: Category) -> Self {
        Self {
            runtime: Some(runtime),
            category,
        }
    }
}

/// A compiled section with allow/deny rules.
#[derive(Debug)]
pub struct CompiledSection {
    pub mode: EnforcementMode,
    pub allow_rules: Vec<CompiledRule>,
    pub deny_rules: Vec<CompiledRule>,
    /// For list-based sections (e.g., protocols).
    pub allowed_values: Vec<String>,
}

impl Default for CompiledSection {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Block,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            allowed_values: Vec::new(),
        }
    }
}

impl CompiledSection {
    pub fn has_allow_rules(&self) -> bool {
        !self.allow_rules.is_empty() || !self.allowed_values.is_empty()
    }

    pub fn has_deny_rules(&self) -> bool {
        !self.deny_rules.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.allow_rules.is_empty()
            && self.deny_rules.is_empty()
            && self.allowed_values.is_empty()
    }
}

/// A compiled rule with pattern and optional constraints.
#[derive(Debug)]
pub struct CompiledRule {
    pub pattern: CompiledPattern,
    pub constraints: Vec<Constraint>,
    /// Per-rule enforcement mode (inherited from source section).
    pub mode: EnforcementMode,
}

impl CompiledRule {
    pub fn new(pattern: CompiledPattern, mode: EnforcementMode) -> Self {
        Self {
            pattern,
            constraints: Vec::new(),
            mode,
        }
    }

    pub fn with_constraints(pattern: CompiledPattern, constraints: Vec<Constraint>, mode: EnforcementMode) -> Self {
        Self {
            pattern,
            constraints,
            mode,
        }
    }
}

/// A constraint on a rule (e.g., argument patterns, file operations).
#[derive(Debug)]
pub struct Constraint {
    pub kind: ConstraintKind,
    pub pattern: CompiledPattern,
}

/// Type of constraint.
#[derive(Debug, Clone)]
pub enum ConstraintKind {
    /// Match any argument.
    AnyArgument,
    /// Match a specific argument by index (0-based).
    ArgumentIndex(usize),
    /// Match allowed operations.
    Operation(Vec<Operation>),
}

/// Enforcement mode for a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Block the operation completely.
    #[default]
    Block,
    /// Prompt for review before allowing.
    Review,
    /// Log the operation but allow it.
    Log,
    /// Warn about the operation but allow it.
    Warn,
    /// No operation - disable this section entirely.
    Noop,
}

impl EnforcementMode {
    /// Parse a mode string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "block" => Some(Self::Block),
            "review" => Some(Self::Review),
            "log" => Some(Self::Log),
            "warn" => Some(Self::Warn),
            "noop" => Some(Self::Noop),
            _ => None,
        }
    }

    /// Check if this mode blocks operations.
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block | Self::Review)
    }
}

/// Runtime environment.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Runtime {
    Python,
    Node,
}

impl Runtime {
    /// Parse a runtime string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "python" => Some(Self::Python),
            "nodejs" => Some(Self::Node),
            _ => None,
        }
    }
}

/// Category of policy section.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Category {
    /// Function calls.
    Functions,
    /// File operations.
    Files,
    /// Environment variable access.
    EnvVars,
    /// Network endpoints (host:port).
    Endpoints,
    /// Domain names.
    Domains,
    /// Network protocols.
    Protocols,
    /// HTTP-specific rules.
    Http,
    /// Command execution.
    Execution,
    /// Direct syscall detection.
    Syscalls,
}

impl Category {
    /// Parse a category string.
    ///
    /// `"network"` is not a Category — it's a special section name that the
    /// compiler expands into Http/Domains/Endpoints/Protocols. Returns None
    /// for it (and any other unknown name).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "symbols" => Some(Self::Functions),
            "files" => Some(Self::Files),
            "envvars" | "env" | "environment" => Some(Self::EnvVars),
            "commands" => Some(Self::Execution),
            "syscalls" => Some(Self::Syscalls),
            _ => None,
        }
    }

    /// Check if this category uses case-insensitive matching.
    pub fn is_case_insensitive(&self) -> bool {
        matches!(self, Self::Domains | Self::Protocols)
    }
}

/// File/resource operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Edit,
    Delete,
    Create,
    Execute,
}

impl Operation {
    /// Parse an operation string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" | "r" => Some(Self::Read),
            "write" | "w" => Some(Self::Write),
            "edit" | "modify" | "update" => Some(Self::Edit),
            "delete" | "remove" | "rm" | "d" => Some(Self::Delete),
            "create" | "new" | "c" => Some(Self::Create),
            "execute" | "exec" | "x" => Some(Self::Execute),
            _ => None,
        }
    }
}
