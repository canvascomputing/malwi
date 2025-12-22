//! TraceEvent builder for consistent event creation.
//!
//! Provides a fluent builder API for creating TraceEvent instances
//! with proper timestamps and consistent formatting.

use malwi_protocol::{Argument, EventType, HookType, NetworkInfo, RuntimeStack, TraceEvent};

/// Builder for creating TraceEvent instances.
///
/// Provides a fluent API for constructing trace events with
/// sensible defaults and consistent timestamp handling.
pub struct EventBuilder {
    hook_type: HookType,
    event_type: EventType,
    function: String,
    arguments: Vec<Argument>,
    native_stack: Vec<usize>,
    runtime_stack: Option<RuntimeStack>,
    network_info: Option<NetworkInfo>,
    source_file: Option<String>,
    source_line: Option<u32>,
}

impl EventBuilder {
    /// Create a new builder for an Enter event.
    ///
    /// # Arguments
    /// * `function` - The bare function name (no prefix)
    pub fn enter(function: impl Into<String>) -> Self {
        Self {
            hook_type: HookType::Native,
            event_type: EventType::Enter,
            function: function.into(),
            arguments: Vec::new(),
            native_stack: Vec::new(),
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
        }
    }

    /// Create a new builder for a Leave event.
    ///
    /// # Arguments
    /// * `function` - The bare function name (no prefix)
    /// * `return_value` - Optional string representation of the return value
    pub fn leave(function: impl Into<String>, return_value: Option<String>) -> Self {
        Self {
            hook_type: HookType::Native,
            event_type: EventType::Leave { return_value },
            function: function.into(),
            arguments: Vec::new(),
            native_stack: Vec::new(),
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
        }
    }

    /// Set the hook type.
    pub fn hook_type(mut self, hook_type: HookType) -> Self {
        self.hook_type = hook_type;
        self
    }

    /// Set the function arguments.
    pub fn arguments(mut self, arguments: Vec<Argument>) -> Self {
        self.arguments = arguments;
        self
    }

    /// Set the native call stack.
    pub fn native_stack(mut self, stack: Vec<usize>) -> Self {
        self.native_stack = stack;
        self
    }

    /// Set the runtime call stack (Python or V8).
    pub fn runtime_stack(mut self, stack: Option<RuntimeStack>) -> Self {
        self.runtime_stack = stack;
        self
    }

    /// Set structured networking metadata.
    pub fn network_info(mut self, network_info: Option<NetworkInfo>) -> Self {
        self.network_info = network_info;
        self
    }

    /// Set the caller's source file and line number.
    pub fn source_location(mut self, file: Option<String>, line: Option<u32>) -> Self {
        self.source_file = file;
        self.source_line = line;
        self
    }

    /// Build the TraceEvent.
    pub fn build(self) -> TraceEvent {
        TraceEvent {
            hook_type: self.hook_type,
            event_type: self.event_type,
            function: self.function,
            arguments: self.arguments,
            native_stack: self.native_stack,
            runtime_stack: self.runtime_stack,
            network_info: self.network_info,
            source_file: self.source_file,
            source_line: self.source_line,
        }
    }
}

/// Create an Enter trace event with a Python function name.
pub fn python_enter(qualified_name: &str) -> EventBuilder {
    EventBuilder::enter(qualified_name).hook_type(HookType::Python)
}

/// Create an Enter trace event with a JavaScript function name.
pub fn js_enter(function_name: &str) -> EventBuilder {
    EventBuilder::enter(function_name).hook_type(HookType::Nodejs)
}

/// Create a Leave trace event with a JavaScript function name.
pub fn js_leave(function_name: &str, return_value: Option<String>) -> EventBuilder {
    EventBuilder::leave(function_name, return_value).hook_type(HookType::Nodejs)
}

/// Create an Enter trace event for an environment variable access.
pub fn envvar_enter(var_name: &str) -> EventBuilder {
    EventBuilder::enter(var_name).hook_type(HookType::EnvVar)
}

/// Create an Enter trace event for an executed command.
///
/// Builds an event for review mode when a child process is about to be spawned/exec'd.
/// The command name should be the basename of the executable.
/// Arguments are formatted from the argv array.
pub fn exec_event(command: &str, argv: Option<Vec<String>>) -> EventBuilder {
    let args: Vec<Argument> = argv
        .unwrap_or_default()
        .into_iter()
        .map(|arg| Argument {
            raw_value: 0,
            display: Some(arg),
        })
        .collect();

    EventBuilder::enter(command.to_string())
        .hook_type(HookType::Exec)
        .arguments(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder_enter() {
        let event = EventBuilder::enter("os.path.join").build();

        assert_eq!(event.function, "os.path.join");
        assert_eq!(event.hook_type, HookType::Native);
        assert!(matches!(event.event_type, EventType::Enter));
    }

    #[test]
    fn test_event_builder_leave() {
        let event = EventBuilder::leave("myFunc", Some("42".to_string())).build();

        assert_eq!(event.function, "myFunc");
        assert_eq!(event.hook_type, HookType::Native);
        assert!(matches!(
            event.event_type,
            EventType::Leave {
                return_value: Some(_)
            }
        ));
    }

    #[test]
    fn test_event_builder_with_options() {
        let args = vec![Argument {
            raw_value: 0,
            display: Some("test".to_string()),
        }];

        let event = EventBuilder::enter("func")
            .hook_type(HookType::Python)
            .arguments(args.clone())
            .build();

        assert_eq!(event.hook_type, HookType::Python);
        assert_eq!(event.arguments.len(), 1);
    }

    #[test]
    fn test_python_enter() {
        let event = python_enter("os.path.join").build();
        assert_eq!(event.function, "os.path.join");
        assert_eq!(event.hook_type, HookType::Python);
    }

    #[test]
    fn test_js_enter() {
        let event = js_enter("fs.readFile").build();
        assert_eq!(event.function, "fs.readFile");
        assert_eq!(event.hook_type, HookType::Nodejs);
    }

    #[test]
    fn test_js_leave() {
        let event = js_leave("myFunc", None).build();
        assert_eq!(event.function, "myFunc");
        assert_eq!(event.hook_type, HookType::Nodejs);
        assert!(matches!(
            event.event_type,
            EventType::Leave { return_value: None }
        ));
    }

    #[test]
    fn test_exec_event() {
        let event = exec_event("curl", Some(vec!["curl".to_string(), "--version".to_string()])).build();
        assert_eq!(event.function, "curl");
        assert_eq!(event.hook_type, HookType::Exec);
        assert!(matches!(event.event_type, EventType::Enter));
        assert_eq!(event.arguments.len(), 2);
        assert_eq!(event.arguments[0].display, Some("curl".to_string()));
        assert_eq!(event.arguments[1].display, Some("--version".to_string()));
    }

    #[test]
    fn test_exec_event_no_args() {
        let event = exec_event("ls", None).build();
        assert_eq!(event.function, "ls");
        assert_eq!(event.hook_type, HookType::Exec);
        assert!(event.arguments.is_empty());
    }

    #[test]
    fn test_source_location() {
        let event = python_enter("json.loads")
            .source_location(Some("script.py".to_string()), Some(42))
            .build();
        assert_eq!(event.source_file.as_deref(), Some("script.py"));
        assert_eq!(event.source_line, Some(42));
    }

    #[test]
    fn test_source_location_none() {
        let event = js_enter("fs.readFile").build();
        assert!(event.source_file.is_none());
        assert!(event.source_line.is_none());
    }
}
