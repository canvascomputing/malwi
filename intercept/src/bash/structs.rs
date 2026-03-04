//! Bash struct parsing: COMMAND, WORD_LIST, WORD_DESC, SHELL_VAR.
//!
//! These structures are read from raw pointers obtained by hooking bash internals.
//! Layouts are verified for bash 5.1–5.3 on 64-bit platforms.

use std::ffi::{c_char, CStr};
use std::sync::atomic::Ordering;

use super::detect::{BASH_DOLLAR_VARS, BASH_LINE_NUMBER};

/// Bash COMMAND struct layout (verified for bash 5.1–5.3, 64-bit):
///   offset 0:  command_type type  (int, 4 bytes) — cm_simple=4
///   offset 4:  int flags          (4 bytes)
///   offset 8:  int line           (4 bytes)
///   offset 16: REDIRECT *redirects (8 bytes, after padding)
///   offset 24: union value        (8 bytes — pointer to sub-struct)
///
/// For cm_simple (type=4), value.Simple points to SIMPLE_COM:
///   offset 0: int flags
///   offset 4: int line
///   offset 8: WORD_LIST *words
///
/// WORD_LIST: { next: *WORD_LIST (offset 0), word: *WORD_DESC (offset 8) }
/// WORD_DESC: { word: *char (offset 0), flags: int (offset 8) }
pub(crate) const BASH_CM_SIMPLE: i32 = 4;
pub(crate) const BASH_COMMAND_TYPE_OFFSET: usize = 0;
pub(crate) const BASH_COMMAND_VALUE_OFFSET: usize = 24;
pub(crate) const BASH_SIMPLE_COM_WORDS_OFFSET: usize = 8;

/// Offset of the `line` field in bash COMMAND struct.
/// COMMAND layout: type(i32@0), flags(i32@4), line(i32@8), ...
const BASH_COMMAND_LINE_OFFSET: usize = 8;

/// SHELL_VAR struct layout (bash 4.4–5.3, 64-bit):
///   offset 0:  char *name          (8 bytes)
///   offset 8:  char *value         (8 bytes)
///   offset 16: char *exportstr     (8 bytes)
///   offset 24: dynamic_value func  (8 bytes)
///   offset 32: assign_func func    (8 bytes)
///   offset 40: int attributes      (4 bytes) — att_exported = 0x1
pub(crate) const SHELL_VAR_ATTRIBUTES_OFFSET: usize = 40;
pub(crate) const ATT_EXPORTED: i32 = 0x1;

/// Read bash source location from global variables.
/// Returns (script_path, line_number).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn get_bash_source_location() -> (Option<String>, Option<u32>) {
    let line_addr = BASH_LINE_NUMBER.load(Ordering::SeqCst);
    let vars_addr = BASH_DOLLAR_VARS.load(Ordering::SeqCst);

    let line = if line_addr != 0 {
        let n = *(line_addr as *const i32);
        if n > 0 {
            Some(n as u32)
        } else {
            None
        }
    } else {
        None
    };

    let file = if vars_addr != 0 {
        // dollar_vars is char*[10]; dollar_vars[0] = $0 (script name)
        let dollar0 = *(vars_addr as *const *const c_char);
        if !dollar0.is_null() {
            let s = CStr::from_ptr(dollar0).to_string_lossy();
            Some(s.into_owned())
        } else {
            None
        }
    } else {
        None
    };

    (file, line)
}

/// Read source location from a COMMAND struct pointer.
/// Uses the COMMAND's line field (more precise than global line_number)
/// and dollar_vars[0] for the filename.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn get_bash_command_source_location(
    cmd_ptr: *const u8,
) -> (Option<String>, Option<u32>) {
    let vars_addr = BASH_DOLLAR_VARS.load(Ordering::SeqCst);

    let line = if !cmd_ptr.is_null() {
        let n = *(cmd_ptr.add(BASH_COMMAND_LINE_OFFSET) as *const i32);
        if n > 0 {
            Some(n as u32)
        } else {
            // Fallback: global line_number (COMMAND.line is 0 for some builtins)
            let line_addr = BASH_LINE_NUMBER.load(Ordering::SeqCst);
            if line_addr != 0 {
                let g = *(line_addr as *const i32);
                if g > 0 {
                    Some(g as u32)
                } else {
                    None
                }
            } else {
                None
            }
        }
    } else {
        None
    };

    let file = if vars_addr != 0 {
        let dollar0 = *(vars_addr as *const *const c_char);
        if !dollar0.is_null() {
            let s = CStr::from_ptr(dollar0).to_string_lossy();
            Some(s.into_owned())
        } else {
            None
        }
    } else {
        None
    };

    (file, line)
}

/// Read the first word from a bash WORD_LIST* structure.
///
/// WORD_LIST layout:
///   offset 0: *next (WORD_LIST*)
///   offset 8: *word (WORD_DESC*)
/// WORD_DESC layout:
///   offset 0: *word (char*)
///   offset 8: flags (int)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn read_word_list_first(list_ptr: *const u8) -> Option<String> {
    if list_ptr.is_null() {
        return None;
    }
    // list->word (WORD_DESC*) is at offset 8 (skip next pointer)
    let word_desc_ptr = *(list_ptr.add(8) as *const *const u8);
    if word_desc_ptr.is_null() {
        return None;
    }
    // word_desc->word (char*) is at offset 0
    let word_ptr = *(word_desc_ptr as *const *const c_char);
    if word_ptr.is_null() {
        return None;
    }
    Some(CStr::from_ptr(word_ptr).to_string_lossy().into_owned())
}

/// Collect all words from a bash WORD_LIST* linked list.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) unsafe fn read_word_list_all(mut list_ptr: *const u8) -> Vec<String> {
    let mut words = Vec::new();
    let mut safety = 0;
    while !list_ptr.is_null() && safety < 1000 {
        // list->word (WORD_DESC*) at offset 8
        let word_desc_ptr = *(list_ptr.add(8) as *const *const u8);
        if !word_desc_ptr.is_null() {
            let word_ptr = *(word_desc_ptr as *const *const c_char);
            if !word_ptr.is_null() {
                words.push(CStr::from_ptr(word_ptr).to_string_lossy().into_owned());
            }
        }
        // list->next (WORD_LIST*) at offset 0
        list_ptr = *(list_ptr as *const *const u8);
        safety += 1;
    }
    words
}
