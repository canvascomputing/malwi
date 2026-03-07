//! Unified agent lifecycle tracker for the CLI event loop.
//!
//! Consolidates agent-tracking state that was split between `EventLoopState`
//! (main.rs) and `SharedState` (agent_server.rs) into a single struct with
//! named methods replacing scattered inline conditionals.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tracks the lifecycle of all connected agents (root + forked children).
pub struct AgentTracker {
    /// Shared counter decremented in the event loop after processing all
    /// preceding events in the FIFO channel.
    active_count: Arc<AtomicU32>,
    /// Whether the root agent has sent its Ready message.
    root_agent_ready: bool,
    /// All agent PIDs that have connected (value unused, key is PID).
    all_pids: HashMap<u32, bool>,
    /// When the root process was first observed dead (for orphan timeout).
    root_dead_since: Option<Instant>,
    /// Cached exit status of the root process.
    process_exit_status: Option<i32>,
    /// PID of the root (spawned) process.
    root_pid: u32,
}

impl AgentTracker {
    /// Create a new tracker for the given root process PID, using pre-created
    /// shared handles (the server needs these before root_pid is known).
    pub fn new(root_pid: u32, active_count: Arc<AtomicU32>) -> Self {
        Self {
            active_count,
            root_agent_ready: false,
            all_pids: HashMap::new(),
            root_dead_since: None,
            process_exit_status: None,
            root_pid,
        }
    }

    /// Record that an agent connected and is ready.
    pub fn on_agent_ready(&mut self, pid: u32) {
        self.all_pids.insert(pid, true);
        if pid == self.root_pid {
            self.root_agent_ready = true;
        }
    }

    /// Whether the root agent has sent its Ready message.
    #[allow(dead_code)]
    pub fn is_root_ready(&self) -> bool {
        self.root_agent_ready
    }

    /// Whether this is the root agent.
    pub fn is_root(&self, pid: u32) -> bool {
        pid == self.root_pid
    }

    /// Record that an agent disconnected. Returns `true` if all agents are
    /// gone AND the root was previously ready (i.e. we should check for exit).
    pub fn on_agent_disconnected(&mut self, pid: u32) -> bool {
        self.all_pids.remove(&pid);
        self.active_count.fetch_sub(1, Ordering::SeqCst);
        self.root_agent_ready && self.active_count.load(Ordering::SeqCst) == 0
    }

    /// Try to reap the root process exit status. Returns `true` if the root
    /// process has exited.
    pub fn try_reap(&mut self) -> bool {
        if self.process_exit_status.is_none() {
            self.process_exit_status = super::try_reap(self.root_pid as i32);
        }
        self.process_exit_status.is_some()
    }

    /// The root process exited before any agent connected.
    pub fn root_died_before_connect(&self) -> bool {
        !self.root_agent_ready && self.process_exit_status.is_some()
    }

    /// Check if we should exit immediately (all agents gone, root dead).
    pub fn should_exit(&self) -> bool {
        self.root_agent_ready
            && self.active_count.load(Ordering::SeqCst) == 0
            && self.process_exit_status.is_some()
    }

    /// Check the orphan timeout: root is dead but some agents haven't sent
    /// Disconnected yet. Returns `true` if the timeout has elapsed.
    pub fn check_orphan_timeout(&mut self, timeout_ms: u64) -> bool {
        if !self.root_agent_ready || self.process_exit_status.is_none() {
            return false;
        }
        match self.root_dead_since {
            None => {
                self.root_dead_since = Some(Instant::now());
                false
            }
            Some(since) => since.elapsed() > Duration::from_millis(timeout_ms),
        }
    }

    /// Get the active agent count (for debug logging).
    pub fn active_count_value(&self) -> u32 {
        self.active_count.load(Ordering::SeqCst)
    }

    /// Get the cached process exit status, if available.
    pub fn exit_status(&self) -> Option<i32> {
        self.process_exit_status
    }
}
