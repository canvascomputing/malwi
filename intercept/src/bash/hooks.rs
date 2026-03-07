//! Bash hook callbacks: shell_execve, execute_command_internal, eval_builtin,
//! source_builtin, find_variable.

use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::atomic::Ordering;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::InvocationContext;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use core::ffi::c_void;
use log::{debug, info};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::exec::SpawnHandler;

use super::detect::BASH_FIND_SHELL_BUILTIN;
use super::structs::{
    get_bash_command_source_location, get_bash_source_location, read_word_list_all,
    read_word_list_first, ATT_EXPORTED, BASH_CM_SIMPLE, BASH_COMMAND_TYPE_OFFSET,
    BASH_COMMAND_VALUE_OFFSET, BASH_SIMPLE_COM_WORDS_OFFSET, SHELL_VAR_ATTRIBUTES_OFFSET,
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    /// Set by shell_execve hook so the subsequent execve hook skips.
    /// shell_execve internally calls execve — without this both hooks fire.
    pub(crate) static IN_SHELL_EXECVE: Cell<bool> = const { Cell::new(false) };

    /// Dedup set for envvar names — reports each variable once per bash command.
    /// Cleared at each execute_command_internal entry.
    pub(crate) static ENVVAR_SEEN: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

// Thread-local storage for the variable name from find_variable's enter callback.
// Used to pass the name to the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
thread_local! {
    static FIND_VAR_NAME: Cell<*const c_char> = const { Cell::new(ptr::null()) };
}

/// Extract the basename from a path.
fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

// ============================================================================
// shell_execve hook
// ============================================================================

/// Hook for bash's shell_execve() — catches all external commands.
/// Signature: int shell_execve(char *command, char **args, char **env)
/// Same as execve — called right before the actual execve() syscall in bash's child process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_shell_execve_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // shell_execve(char *command, char **args, char **env)
    IN_SHELL_EXECVE.with(|f| f.set(true));

    let path_ptr = crate::invocation::get_nth_argument(context, 0) as *const c_char;
    let path = if !path_ptr.is_null() {
        Some(CStr::from_ptr(path_ptr).to_string_lossy().into_owned())
    } else {
        None
    };

    let argv_ptr = crate::invocation::get_nth_argument(context, 1) as *const *const c_char;
    let argv = crate::exec::spawn::parse_argv(argv_ptr);

    debug!("shell_execve() enter: path={:?}, argv={:?}", path, argv);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy BEFORE the exec completes
    if !crate::exec::spawn::check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Block by replacing path with an invalid one
        static BLOCKED_PATH: &[u8] = b"/usr/bin/false\0";
        crate::invocation::replace_nth_argument(context, 0, BLOCKED_PATH.as_ptr() as *mut c_void);
        info!("BLOCKED bash shell_execve: {:?}", path);
        return;
    }

    let native_stack = crate::exec::spawn::should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(crate::exec::SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
            runtime_stack: None,
        });
    }
}

// ============================================================================
// execute_command_internal hook
// ============================================================================

/// Hook for bash's execute_command_internal() — catches ALL commands (builtins + externals).
///
/// Signature: int execute_command_internal(COMMAND *command, int asynchronous,
///            int pipe_in, int pipe_out, struct fd_bitmap *fds_to_close)
///
/// For cm_simple commands, reads the first word from the COMMAND struct to get the command name.
/// This hook only handles tracing/policy for commands that don't go through shell_execve
/// (i.e., builtins and shell functions). External commands are handled by the shell_execve hook.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_execute_command_internal_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    // Clear envvar dedup set at each new bash command
    ENVVAR_SEEN.with(|set| set.borrow_mut().clear());

    // arg 0 = COMMAND *command
    let cmd_ptr = crate::invocation::get_nth_argument(context, 0) as *const u8;
    if cmd_ptr.is_null() {
        return;
    }

    // Read command->type (int at offset 0)
    let cmd_type = *(cmd_ptr.add(BASH_COMMAND_TYPE_OFFSET) as *const i32);
    if cmd_type != BASH_CM_SIMPLE {
        return; // Only process simple commands (not for/while/if/etc.)
    }

    // Read command->value.Simple (pointer at offset 24)
    let simple_ptr = *(cmd_ptr.add(BASH_COMMAND_VALUE_OFFSET) as *const *const u8);
    if simple_ptr.is_null() {
        return;
    }

    // Read Simple->words (WORD_LIST* at offset 8)
    let words_ptr = *(simple_ptr.add(BASH_SIMPLE_COM_WORDS_OFFSET) as *const *const u8);
    if words_ptr.is_null() {
        return;
    }

    // Read first word: words->word->word
    let first_word = match read_word_list_first(words_ptr) {
        Some(w) => w,
        None => return,
    };

    // Determine if this is a builtin or shell function.
    // External commands are handled by the shell_execve hook (with resolved path + argv),
    // so we skip them here to avoid double-tracing.
    if first_word.contains('/') {
        return; // Explicit path like /usr/bin/curl — definitely external
    }

    // Use find_shell_builtin to check if it's a builtin
    let find_builtin_addr = BASH_FIND_SHELL_BUILTIN.load(Ordering::Acquire);
    if find_builtin_addr != 0 {
        let name_cstr = CString::new(first_word.as_str()).ok();
        if let Some(name_cstr) = name_cstr {
            type FindBuiltinFn = unsafe extern "C" fn(*const c_char) -> *const u8;
            let find_builtin: FindBuiltinFn = std::mem::transmute(find_builtin_addr);
            let result = find_builtin(name_cstr.as_ptr());
            if result.is_null() {
                // Not a builtin — it's an external command that shell_execve will handle
                return;
            }
        }
    }

    // Collect all words for argv
    let words = read_word_list_all(words_ptr);

    debug!(
        "execute_command_internal() enter: cm_simple, command={}",
        first_word
    );

    let path = Some(first_word.clone());
    let argv = Some(words);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_command_source_location(cmd_ptr);

    // Check review mode / policy
    if !crate::exec::spawn::check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Block by replacing the COMMAND pointer with null.
        // execute_command_internal handles null by returning early.
        crate::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash command: {}", first_word);
        return;
    }

    // Send exec event to CLI (only if exec filters are active)
    if crate::exec::filter::has_filters() {
        let cmd_name = basename(&first_word);
        let (matches, _) = crate::exec::filter::check_filter(cmd_name);
        if matches {
            let native_stack = crate::exec::spawn::should_capture_stack(&path, &argv, context);
            if let Some(agent) = crate::Agent::get() {
                let pid = std::process::id();
                agent.on_exec_imminent(crate::exec::SpawnInfo {
                    child_pid: pid,
                    path,
                    argv,
                    native_stack,
                    source_file,
                    source_line,
                    runtime_stack: None,
                });
            }
        }
    }
}

// ============================================================================
// eval_builtin hook
// ============================================================================

/// Hook for bash's eval_builtin() — catches `eval "code"`.
/// Signature: int eval_builtin(WORD_LIST *list)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_eval_builtin_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let list_ptr = crate::invocation::get_nth_argument(context, 0) as *const u8;

    let words = read_word_list_all(list_ptr);
    let eval_code = words.join(" ");
    debug!("eval_builtin() enter: code={}", eval_code);

    // Build argv as ["eval", <code>...]
    let mut argv_vec = vec!["eval".to_string()];
    argv_vec.extend(words);
    let path = Some("eval".to_string());
    let argv = Some(argv_vec);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy
    if !crate::exec::spawn::check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Replace list arg with null — eval_builtin returns immediately for null list
        crate::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash eval: {}", eval_code);
        return;
    }

    let native_stack = crate::exec::spawn::should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(crate::exec::SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
            runtime_stack: None,
        });
    }
}

// ============================================================================
// source_builtin hook
// ============================================================================

/// Hook for bash's source_builtin() — catches `source file.sh` / `. file.sh`.
/// Signature: int source_builtin(WORD_LIST *list)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_source_builtin_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let list_ptr = crate::invocation::get_nth_argument(context, 0) as *const u8;

    let filename = read_word_list_first(list_ptr).unwrap_or_default();
    debug!("source_builtin() enter: file={}", filename);

    let path = Some("source".to_string());
    let argv = Some(vec!["source".to_string(), filename.clone()]);

    // Capture source location BEFORE review check so denied events also have it
    let (source_file, source_line) = get_bash_source_location();

    // Check review mode / policy
    if !crate::exec::spawn::check_exec_review(&path, &argv, source_file.as_deref(), source_line) {
        // Replace list arg with null — source_builtin returns EX_USAGE for null list
        crate::invocation::replace_nth_argument(context, 0, ptr::null_mut());
        info!("BLOCKED bash source: {}", filename);
        return;
    }

    let native_stack = crate::exec::spawn::should_capture_stack(&path, &argv, context);

    // Send exec event to CLI
    if let Some(agent) = crate::Agent::get() {
        let pid = std::process::id();
        agent.on_exec_imminent(crate::exec::SpawnInfo {
            child_pid: pid,
            path,
            argv,
            native_stack,
            source_file,
            source_line,
            runtime_stack: None,
        });
    }
}

// ============================================================================
// find_variable hooks (environment variable access detection)
// ============================================================================

/// Enter callback for bash's find_variable(const char *name).
/// Stores the name pointer for the leave callback.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_find_variable_enter(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let name_ptr = crate::invocation::get_nth_argument(context, 0) as *const c_char;
    FIND_VAR_NAME.with(|cell| cell.set(name_ptr));
}

/// Leave callback for bash's find_variable.
/// Checks the return value (SHELL_VAR*) for att_exported flag.
/// If exported, sends an EnvVar trace event.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe extern "C" fn on_find_variable_leave(
    context: *mut InvocationContext,
    _user_data: *mut c_void,
) {
    let shell_var = crate::invocation::get_return_value(context) as *const u8;
    if shell_var.is_null() {
        return; // Variable not found
    }

    // Check att_exported flag at offset 40
    let attributes = *(shell_var.add(SHELL_VAR_ATTRIBUTES_OFFSET) as *const i32);
    if attributes & ATT_EXPORTED == 0 {
        return; // Not an exported (environment) variable — skip
    }

    // Read the name from enter callback
    let name_ptr = FIND_VAR_NAME.with(|cell| cell.get());
    if name_ptr.is_null() {
        return;
    }
    let name = CStr::from_ptr(name_ptr).to_string_lossy();

    // Dedup: skip if already seen in this command
    let is_new = ENVVAR_SEEN.with(|set| set.borrow_mut().insert(name.to_string()));
    if !is_new {
        return;
    }

    // Check agent-side deny filter — if blocked, replace return value with NULL
    // so bash sees the variable as unset (prevents secret leakage).
    let blocked = crate::exec::envvar::should_block(&name);
    if blocked {
        crate::invocation::replace_return_value(context, ptr::null_mut());
    }

    // Send trace event regardless (blocked or not — CLI decides display)
    if let Some(agent) = crate::Agent::get() {
        let (source_file, source_line) = get_bash_source_location();
        let event = crate::tracing::event::envvar_enter(&name)
            .source_location(source_file, source_line)
            .build();
        let _ = agent.send_event(event);
    }
}
