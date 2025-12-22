use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse YAML: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("pattern compilation error: {0}")]
    Pattern(#[from] PatternError),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unsupported policy version: {0} (supported: 1)")]
    UnsupportedVersion(u32),

    #[error("missing required 'version' field")]
    MissingVersion,

    #[error("section '{0}' uses removed @ syntax; use 'warn:', 'log:', 'review:', or 'noop:' key inside the section instead")]
    DeprecatedAtSyntax(String),

    #[error("unknown section: {0}")]
    UnknownSection(String),

    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("invalid regex pattern '{pattern}': {reason}")]
    InvalidRegex { pattern: String, reason: String },

    #[error("invalid constraint format in rule: {0}")]
    InvalidConstraint(String),
}

#[derive(Debug, Error)]
pub enum PatternError {
    #[error("invalid regex pattern '{pattern}': {reason}")]
    InvalidRegex { pattern: String, reason: String },

    #[error("invalid glob pattern: {0}")]
    InvalidGlob(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;
pub type PatternResult<T> = std::result::Result<T, PatternError>;
