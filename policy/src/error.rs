use std::fmt;

#[derive(Debug)]
pub enum PolicyError {
    YamlParse(crate::yaml::YamlError),
    Validation(ValidationError),
    Pattern(PatternError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::YamlParse(e) => write!(f, "failed to parse YAML: {}", e),
            PolicyError::Validation(e) => write!(f, "validation error: {}", e),
            PolicyError::Pattern(e) => write!(f, "pattern compilation error: {}", e),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyError::YamlParse(e) => Some(e),
            PolicyError::Validation(e) => Some(e),
            PolicyError::Pattern(e) => Some(e),
        }
    }
}

impl From<crate::yaml::YamlError> for PolicyError {
    fn from(e: crate::yaml::YamlError) -> Self {
        PolicyError::YamlParse(e)
    }
}

impl From<ValidationError> for PolicyError {
    fn from(e: ValidationError) -> Self {
        PolicyError::Validation(e)
    }
}

impl From<PatternError> for PolicyError {
    fn from(e: PatternError) -> Self {
        PolicyError::Pattern(e)
    }
}

#[derive(Debug)]
pub enum ValidationError {
    UnsupportedVersion(u32),
    MissingVersion,
    DeprecatedAtSyntax(String),
    UnknownSection(String),
    InvalidOperation(String),
    InvalidProtocol(String),
    InvalidRegex { pattern: String, reason: String },
    InvalidConstraint(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::UnsupportedVersion(v) => {
                write!(f, "unsupported policy version: {} (supported: 1)", v)
            }
            ValidationError::MissingVersion => write!(f, "missing required 'version' field"),
            ValidationError::DeprecatedAtSyntax(s) => write!(
                f,
                "section '{}' uses removed @ syntax; use 'warn:', 'log:', 'review:', or 'noop:' key inside the section instead",
                s
            ),
            ValidationError::UnknownSection(s) => write!(f, "unknown section: {}", s),
            ValidationError::InvalidOperation(s) => write!(f, "invalid operation: {}", s),
            ValidationError::InvalidProtocol(s) => write!(f, "invalid protocol: {}", s),
            ValidationError::InvalidRegex { pattern, reason } => {
                write!(f, "invalid regex pattern '{}': {}", pattern, reason)
            }
            ValidationError::InvalidConstraint(s) => {
                write!(f, "invalid constraint format in rule: {}", s)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug)]
pub enum PatternError {
    InvalidRegex { pattern: String, reason: String },
    InvalidGlob(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternError::InvalidRegex { pattern, reason } => {
                write!(f, "invalid regex pattern '{}': {}", pattern, reason)
            }
            PatternError::InvalidGlob(s) => write!(f, "invalid glob pattern: {}", s),
        }
    }
}

impl std::error::Error for PatternError {}

pub type Result<T> = std::result::Result<T, PolicyError>;
pub type PatternResult<T> = std::result::Result<T, PatternError>;
