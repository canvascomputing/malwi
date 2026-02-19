//! Native function argument formatting.
//!
//! Provides human-readable display values for arguments to known native functions
//! (e.g., showing file paths instead of raw pointers for open()).

use std::ffi::CStr;
use std::os::raw::c_char;

use malwi_protocol::Argument;

use crate::tracing::format::truncate;

const MAX_STRING_LEN: usize = 256;
const MAX_BUFFER_PREVIEW: usize = 64;

/// Format arguments for known native functions.
///
/// Sets the `display` field on arguments based on the function being called.
/// Unknown functions are left unchanged (raw hex values).
pub fn format_native_arguments(function: &str, arguments: &mut [Argument]) {
    match function {
        "open" | "_open" => format_open(arguments),
        "openat" | "_openat" => format_openat(arguments),
        "read" | "_read" => format_read(arguments),
        "write" | "_write" => format_write(arguments),
        "close" | "_close" => format_close(arguments),
        "stat" | "stat64" | "_stat" | "$INODE64" => format_stat(arguments),
        "lstat" | "lstat64" | "_lstat" => format_stat(arguments),
        "fstat" | "fstat64" | "_fstat" => format_fstat(arguments),
        "access" | "_access" => format_access(arguments),
        "unlink" | "_unlink" => format_path_arg(arguments, 0),
        "rename" | "_rename" => format_rename(arguments),
        "mkdir" | "_mkdir" => format_mkdir(arguments),
        "rmdir" | "_rmdir" => format_path_arg(arguments, 0),
        "socket" | "_socket" => format_socket(arguments),
        "connect" | "_connect" => format_connect(arguments),
        "bind" | "_bind" => format_bind(arguments),
        "sendto" | "_sendto" => format_sendto(arguments),
        "recvfrom" | "_recvfrom" => format_recvfrom(arguments),
        "execve" | "_execve" => format_execve(arguments),
        "dlopen" => format_dlopen(arguments),
        "mmap" | "_mmap" => format_mmap(arguments),
        "munmap" | "_munmap" => format_munmap(arguments),
        "dup" | "_dup" => format_fd_arg(arguments, 0),
        "dup2" | "_dup2" => format_dup2(arguments),
        "pipe" | "_pipe" => {} // Array of int, hard to format
        "fcntl" | "_fcntl" => format_fcntl(arguments),
        "ioctl" | "_ioctl" => format_ioctl(arguments),
        "getpid" | "_getpid" | "getppid" | "_getppid" => {} // No args
        "fork" | "_fork" | "vfork" | "_vfork" => {}         // No args
        "chdir" | "_chdir" => format_path_arg(arguments, 0),
        "getcwd" | "_getcwd" => {} // Returns path, hard to preview
        "link" | "_link" | "symlink" | "_symlink" => format_link(arguments),
        "readlink" | "_readlink" => format_path_arg(arguments, 0),
        "chmod" | "_chmod" => format_chmod(arguments),
        "chown" | "_chown" => format_chown(arguments),

        // DNS resolution functions
        "getaddrinfo" | "_getaddrinfo" => format_getaddrinfo(arguments),
        "gethostbyname" | "_gethostbyname" => format_path_arg(arguments, 0),
        "gethostbyname2" | "_gethostbyname2" => format_gethostbyname2(arguments),
        "getnameinfo" | "_getnameinfo" => format_getnameinfo(arguments),

        // Network functions
        "listen" | "_listen" => format_listen(arguments),
        "accept" | "_accept" => format_accept(arguments),
        "accept4" => format_accept4(arguments),
        "shutdown" | "_shutdown" => format_shutdown(arguments),
        "getsockopt" | "_getsockopt" => format_getsockopt(arguments),
        "setsockopt" | "_setsockopt" => format_setsockopt(arguments),
        "getpeername" | "_getpeername" => format_getpeername(arguments),
        "getsockname" | "_getsockname" => format_getsockname(arguments),
        "send" | "_send" => format_send(arguments),
        "recv" | "_recv" => format_recv(arguments),

        // File I/O extensions
        "pread" | "_pread" | "pread64" => format_pread(arguments),
        "pwrite" | "_pwrite" | "pwrite64" => format_pwrite(arguments),
        "lseek" | "_lseek" | "lseek64" => format_lseek(arguments),
        "truncate" | "_truncate" | "truncate64" => format_truncate(arguments),
        "ftruncate" | "_ftruncate" | "ftruncate64" => format_ftruncate(arguments),
        "fsync" | "_fsync" => format_fd_arg(arguments, 0),
        "fdatasync" | "_fdatasync" => format_fd_arg(arguments, 0),
        "fchmod" | "_fchmod" => format_fchmod(arguments),
        "fchown" | "_fchown" => format_fchown(arguments),
        "fchdir" | "_fchdir" => format_fd_arg(arguments, 0),

        _ => {} // Unknown function - leave as raw
    }
}

/// Format open(path, flags, mode) arguments.
fn format_open(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path (char*)
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: flags (int)
    if args.len() >= 2 {
        args[1].display = Some(format_open_flags(args[1].raw_value as i32));
    }
    // arg2: mode (mode_t) - only relevant with O_CREAT
    if args.len() >= 3 {
        let flags = args[1].raw_value as i32;
        if flags & 0x200 != 0 {
            // O_CREAT
            args[2].display = Some(format!("mode={:#o}", args[2].raw_value));
        }
    }
}

/// Format openat(dirfd, path, flags, mode) arguments.
fn format_openat(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: dirfd
    args[0].display = Some(format_dirfd(args[0].raw_value as i32));
    // arg1: path (char*)
    if args.len() >= 2 {
        if let Some(path) = read_c_string(args[1].raw_value) {
            args[1].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
        }
    }
    // arg2: flags
    if args.len() >= 3 {
        args[2].display = Some(format_open_flags(args[2].raw_value as i32));
    }
    // arg3: mode (only with O_CREAT)
    if args.len() >= 4 {
        let flags = args[2].raw_value as i32;
        if flags & 0x200 != 0 {
            args[3].display = Some(format!("mode={:#o}", args[3].raw_value));
        }
    }
}

/// Format read(fd, buf, count) arguments.
fn format_read(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        args[2].display = Some(format!("count={}", args[2].raw_value));
    }
}

/// Format write(fd, buf, count) arguments.
fn format_write(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Optionally preview buffer contents
        if let Some(preview) = read_buffer_preview(args[1].raw_value, args[2].raw_value) {
            args[1].display = Some(format!("\"{}\"", preview));
        } else {
            args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        }
        args[2].display = Some(format!("count={}", args[2].raw_value));
    }
}

/// Format close(fd) argument.
fn format_close(args: &mut [Argument]) {
    if !args.is_empty() {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
    }
}

/// Format stat(path, buf) arguments.
fn format_stat(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path (char*)
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: buf (struct stat*) - just show address
    if args.len() >= 2 {
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
    }
}

/// Format fstat(fd, buf) arguments.
fn format_fstat(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
    }
}

/// Format access(path, mode) arguments.
fn format_access(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: mode
    if args.len() >= 2 {
        args[1].display = Some(format_access_mode(args[1].raw_value as i32));
    }
}

/// Format a single path argument at the given index.
fn format_path_arg(args: &mut [Argument], index: usize) {
    if args.len() > index {
        if let Some(path) = read_c_string(args[index].raw_value) {
            args[index].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
        }
    }
}

/// Format a single fd argument at the given index.
fn format_fd_arg(args: &mut [Argument], index: usize) {
    if args.len() > index {
        args[index].display = Some(format!("fd={}", args[index].raw_value));
    }
}

/// Format rename(old, new) arguments.
fn format_rename(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: old path
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: new path
    if args.len() >= 2 {
        if let Some(path) = read_c_string(args[1].raw_value) {
            args[1].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
        }
    }
}

/// Format mkdir(path, mode) arguments.
fn format_mkdir(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: mode
    if args.len() >= 2 {
        args[1].display = Some(format!("mode={:#o}", args[1].raw_value));
    }
}

/// Format socket(domain, type, protocol) arguments.
fn format_socket(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format_socket_domain(args[0].raw_value as i32));
        args[1].display = Some(format_socket_type(args[1].raw_value as i32));
        args[2].display = Some(format!("protocol={}", args[2].raw_value));
    }
}

/// Format connect(fd, addr, addrlen) arguments.
fn format_connect(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = format_sockaddr(args[1].raw_value, args[2].raw_value);
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
    }
}

/// Format bind(fd, addr, addrlen) arguments.
fn format_bind(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = format_sockaddr(args[1].raw_value, args[2].raw_value);
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
    }
}

/// Format sendto(fd, buf, len, flags, dest_addr, addrlen) arguments.
fn format_sendto(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Preview buffer if possible
        if let Some(preview) = read_buffer_preview(args[1].raw_value, args[2].raw_value) {
            args[1].display = Some(format!("\"{}\"", preview));
        } else {
            args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        }
        args[2].display = Some(format!("len={}", args[2].raw_value));
        args[3].display = Some(format!("flags={:#x}", args[3].raw_value));
    }
    // Optional dest_addr
    if args.len() >= 6 && args[4].raw_value != 0 {
        args[4].display = format_sockaddr(args[4].raw_value, args[5].raw_value);
        args[5].display = Some(format!("addrlen={}", args[5].raw_value));
    }
}

/// Format recvfrom(fd, buf, len, flags, src_addr, addrlen) arguments.
fn format_recvfrom(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        args[2].display = Some(format!("len={}", args[2].raw_value));
        args[3].display = Some(format!("flags={:#x}", args[3].raw_value));
    }
}

/// Format execve(path, argv, envp) arguments.
fn format_execve(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: argv - show first few args if possible
    if args.len() >= 2 && args[1].raw_value != 0 {
        if let Some(argv_preview) = read_argv_preview(args[1].raw_value) {
            args[1].display = Some(argv_preview);
        } else {
            args[1].display = Some(format!("argv={:#x}", args[1].raw_value));
        }
    }
    // arg2: envp - just show pointer
    if args.len() >= 3 {
        args[2].display = Some(format!("envp={:#x}", args[2].raw_value));
    }
}

/// Format dlopen(path, flags) arguments.
fn format_dlopen(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    // arg0: path (can be NULL)
    if args[0].raw_value == 0 {
        args[0].display = Some("NULL".to_string());
    } else if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    // arg1: flags
    if args.len() >= 2 {
        args[1].display = Some(format_dlopen_flags(args[1].raw_value as i32));
    }
}

/// Format mmap(addr, len, prot, flags, fd, offset) arguments.
fn format_mmap(args: &mut [Argument]) {
    if args.len() >= 6 {
        args[0].display = Some(if args[0].raw_value == 0 {
            "NULL".to_string()
        } else {
            format!("addr={:#x}", args[0].raw_value)
        });
        args[1].display = Some(format!("len={}", args[1].raw_value));
        args[2].display = Some(format_mmap_prot(args[2].raw_value as i32));
        args[3].display = Some(format_mmap_flags(args[3].raw_value as i32));
        args[4].display = Some(format!("fd={}", args[4].raw_value as i32));
        args[5].display = Some(format!("offset={}", args[5].raw_value));
    }
}

/// Format munmap(addr, len) arguments.
fn format_munmap(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("addr={:#x}", args[0].raw_value));
        args[1].display = Some(format!("len={}", args[1].raw_value));
    }
}

/// Format dup2(oldfd, newfd) arguments.
fn format_dup2(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("oldfd={}", args[0].raw_value));
        args[1].display = Some(format!("newfd={}", args[1].raw_value));
    }
}

/// Format fcntl(fd, cmd, ...) arguments.
fn format_fcntl(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format_fcntl_cmd(args[1].raw_value as i32));
    }
}

/// Format ioctl(fd, request, ...) arguments.
fn format_ioctl(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("request={:#x}", args[1].raw_value));
    }
}

/// Format link/symlink(path1, path2) arguments.
fn format_link(args: &mut [Argument]) {
    format_rename(args); // Same format: two paths
}

/// Format chmod(path, mode) arguments.
fn format_chmod(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    if args.len() >= 2 {
        args[1].display = Some(format!("mode={:#o}", args[1].raw_value));
    }
}

/// Format chown(path, owner, group) arguments.
fn format_chown(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    if args.len() >= 2 {
        args[1].display = Some(format!("owner={}", args[1].raw_value as i32));
    }
    if args.len() >= 3 {
        args[2].display = Some(format!("group={}", args[2].raw_value as i32));
    }
}

// ============================================================================
// Network function formatters
// ============================================================================

/// Format listen(fd, backlog) arguments.
fn format_listen(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("backlog={}", args[1].raw_value));
    }
}

/// Format accept(fd, addr, addrlen) arguments.
fn format_accept(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Try to format sockaddr if addr is not NULL
        if args[1].raw_value != 0 {
            args[1].display = format_sockaddr(args[1].raw_value, args[2].raw_value);
        } else {
            args[1].display = Some("NULL".to_string());
        }
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
    }
}

/// Format accept4(fd, addr, addrlen, flags) arguments.
fn format_accept4(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Try to format sockaddr if addr is not NULL
        if args[1].raw_value != 0 {
            args[1].display = format_sockaddr(args[1].raw_value, args[2].raw_value);
        } else {
            args[1].display = Some("NULL".to_string());
        }
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
        args[3].display = Some(format_accept4_flags(args[3].raw_value as i32));
    }
}

/// Format shutdown(fd, how) arguments.
fn format_shutdown(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format_shutdown_how(args[1].raw_value as i32));
    }
}

/// Format getsockopt(fd, level, optname, optval, optlen) arguments.
fn format_getsockopt(args: &mut [Argument]) {
    if args.len() >= 5 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        let level = args[1].raw_value as i32;
        args[1].display = Some(format_socket_level(level));
        args[2].display = Some(format_socket_optname(level, args[2].raw_value as i32));
        args[3].display = Some(format!("optval={:#x}", args[3].raw_value));
        args[4].display = Some(format!("optlen={:#x}", args[4].raw_value));
    }
}

/// Format setsockopt(fd, level, optname, optval, optlen) arguments.
fn format_setsockopt(args: &mut [Argument]) {
    if args.len() >= 5 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        let level = args[1].raw_value as i32;
        args[1].display = Some(format_socket_level(level));
        args[2].display = Some(format_socket_optname(level, args[2].raw_value as i32));
        args[3].display = Some(format!("optval={:#x}", args[3].raw_value));
        args[4].display = Some(format!("optlen={}", args[4].raw_value));
    }
}

/// Format getpeername(fd, addr, addrlen) arguments.
fn format_getpeername(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("addr={:#x}", args[1].raw_value));
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
    }
}

/// Format getsockname(fd, addr, addrlen) arguments.
fn format_getsockname(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("addr={:#x}", args[1].raw_value));
        args[2].display = Some(format!("addrlen={}", args[2].raw_value));
    }
}

/// Format send(fd, buf, len, flags) arguments.
fn format_send(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Preview buffer if possible
        if let Some(preview) = read_buffer_preview(args[1].raw_value, args[2].raw_value) {
            args[1].display = Some(format!("\"{}\"", preview));
        } else {
            args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        }
        args[2].display = Some(format!("len={}", args[2].raw_value));
        args[3].display = Some(format!("flags={:#x}", args[3].raw_value));
    }
}

/// Format recv(fd, buf, len, flags) arguments.
fn format_recv(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        args[2].display = Some(format!("len={}", args[2].raw_value));
        args[3].display = Some(format!("flags={:#x}", args[3].raw_value));
    }
}

// ============================================================================
// File I/O extension formatters
// ============================================================================

/// Format pread(fd, buf, count, offset) arguments.
fn format_pread(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        args[2].display = Some(format!("count={}", args[2].raw_value));
        args[3].display = Some(format!("offset={}", args[3].raw_value));
    }
}

/// Format pwrite(fd, buf, count, offset) arguments.
fn format_pwrite(args: &mut [Argument]) {
    if args.len() >= 4 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        // Preview buffer if possible
        if let Some(preview) = read_buffer_preview(args[1].raw_value, args[2].raw_value) {
            args[1].display = Some(format!("\"{}\"", preview));
        } else {
            args[1].display = Some(format!("buf={:#x}", args[1].raw_value));
        }
        args[2].display = Some(format!("count={}", args[2].raw_value));
        args[3].display = Some(format!("offset={}", args[3].raw_value));
    }
}

/// Format lseek(fd, offset, whence) arguments.
fn format_lseek(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("offset={}", args[1].raw_value as i64));
        args[2].display = Some(format_seek_whence(args[2].raw_value as i32));
    }
}

/// Format truncate(path, length) arguments.
fn format_truncate(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }
    if let Some(path) = read_c_string(args[0].raw_value) {
        args[0].display = Some(format!("\"{}\"", truncate(&path, MAX_STRING_LEN)));
    }
    if args.len() >= 2 {
        args[1].display = Some(format!("length={}", args[1].raw_value));
    }
}

/// Format ftruncate(fd, length) arguments.
fn format_ftruncate(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("length={}", args[1].raw_value));
    }
}

/// Format fchmod(fd, mode) arguments.
fn format_fchmod(args: &mut [Argument]) {
    if args.len() >= 2 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("mode={:#o}", args[1].raw_value));
    }
}

/// Format fchown(fd, owner, group) arguments.
fn format_fchown(args: &mut [Argument]) {
    if args.len() >= 3 {
        args[0].display = Some(format!("fd={}", args[0].raw_value));
        args[1].display = Some(format!("owner={}", args[1].raw_value as i32));
        args[2].display = Some(format!("group={}", args[2].raw_value as i32));
    }
}

// ============================================================================
// DNS resolution formatters
// ============================================================================

/// Format getaddrinfo(node, service, hints, res) arguments.
fn format_getaddrinfo(args: &mut [Argument]) {
    // arg0: node (const char* — hostname)
    if !args.is_empty() {
        if args[0].raw_value == 0 {
            args[0].display = Some("NULL".to_string());
        } else if let Some(host) = read_c_string(args[0].raw_value) {
            args[0].display = Some(format!("\"{}\"", truncate(&host, MAX_STRING_LEN)));
        }
    }
    // arg1: service (const char* — port/service name)
    if args.len() >= 2 {
        if args[1].raw_value == 0 {
            args[1].display = Some("NULL".to_string());
        } else if let Some(svc) = read_c_string(args[1].raw_value) {
            args[1].display = Some(format!("\"{}\"", svc));
        }
    }
    // arg2: hints — just show pointer
    if args.len() >= 3 {
        args[2].display = Some(format!("hints={:#x}", args[2].raw_value));
    }
    // arg3: res — just show pointer
    if args.len() >= 4 {
        args[3].display = Some(format!("res={:#x}", args[3].raw_value));
    }
}

/// Format gethostbyname2(name, af) arguments.
fn format_gethostbyname2(args: &mut [Argument]) {
    // arg0: hostname (const char*)
    if !args.is_empty() {
        if let Some(host) = read_c_string(args[0].raw_value) {
            args[0].display = Some(format!("\"{}\"", truncate(&host, MAX_STRING_LEN)));
        }
    }
    // arg1: address family (int)
    if args.len() >= 2 {
        args[1].display = Some(format_socket_domain(args[1].raw_value as i32));
    }
}

/// Format getnameinfo(sa, salen, host, hostlen, serv, servlen, flags) arguments.
fn format_getnameinfo(args: &mut [Argument]) {
    // arg0: sockaddr
    if args.len() >= 2 {
        args[0].display = format_sockaddr(args[0].raw_value, args[1].raw_value);
        args[1].display = Some(format!("salen={}", args[1].raw_value));
    }
    // arg2-6: output buffers and flags — just show pointers
    if args.len() >= 3 {
        args[2].display = Some(format!("host={:#x}", args[2].raw_value));
    }
    if args.len() >= 4 {
        args[3].display = Some(format!("hostlen={}", args[3].raw_value));
    }
    if args.len() >= 5 {
        args[4].display = Some(format!("serv={:#x}", args[4].raw_value));
    }
    if args.len() >= 6 {
        args[5].display = Some(format!("servlen={}", args[5].raw_value));
    }
    if args.len() >= 7 {
        args[6].display = Some(format!("flags={:#x}", args[6].raw_value));
    }
}

// ============================================================================
// Helper functions for reading memory and formatting constants
// ============================================================================

/// Safely read a C string from process memory.
fn read_c_string(ptr: usize) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    unsafe {
        let c_str = CStr::from_ptr(ptr as *const c_char);
        c_str.to_str().ok().map(String::from)
    }
}

/// Read buffer preview (for write calls) - only if content is printable.
fn read_buffer_preview(ptr: usize, len: usize) -> Option<String> {
    if ptr == 0 || len == 0 {
        return None;
    }
    let preview_len = len.min(MAX_BUFFER_PREVIEW);
    unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, preview_len);
        // Only show if mostly printable
        if slice
            .iter()
            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            let s = String::from_utf8_lossy(slice);
            let truncated = if len > MAX_BUFFER_PREVIEW {
                format!("{}...", s)
            } else {
                s.into_owned()
            };
            return Some(truncated);
        }
    }
    None
}

/// Read argv preview (first few arguments).
fn read_argv_preview(argv_ptr: usize) -> Option<String> {
    if argv_ptr == 0 {
        return None;
    }
    let mut args = Vec::new();
    let max_args = 4;

    unsafe {
        let argv = argv_ptr as *const *const c_char;
        for i in 0..max_args {
            let arg_ptr = *argv.add(i);
            if arg_ptr.is_null() {
                break;
            }
            if let Ok(s) = CStr::from_ptr(arg_ptr).to_str() {
                args.push(format!("\"{}\"", truncate(s, 32)));
            }
        }
    }

    if args.is_empty() {
        None
    } else {
        Some(format!("[{}]", args.join(", ")))
    }
}

/// Format dirfd argument (AT_FDCWD handling).
fn format_dirfd(fd: i32) -> String {
    // AT_FDCWD is -100 on Linux, -2 on macOS
    if fd == -100 || fd == -2 {
        "AT_FDCWD".to_string()
    } else {
        format!("dirfd={}", fd)
    }
}

/// Format open() flags.
fn format_open_flags(flags: i32) -> String {
    let mut parts = Vec::new();

    // Access mode (lowest 2 bits)
    match flags & 0x3 {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => {}
    }

    // Common flags (values may differ between Linux/macOS)
    #[cfg(target_os = "linux")]
    {
        if flags & 0x40 != 0 {
            parts.push("O_CREAT");
        }
        if flags & 0x200 != 0 {
            parts.push("O_TRUNC");
        }
        if flags & 0x400 != 0 {
            parts.push("O_APPEND");
        }
        if flags & 0x80 != 0 {
            parts.push("O_EXCL");
        }
        if flags & 0x800 != 0 {
            parts.push("O_NONBLOCK");
        }
        if flags & 0x100000 != 0 {
            parts.push("O_DIRECTORY");
        }
        if flags & 0x20000 != 0 {
            parts.push("O_CLOEXEC");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if flags & 0x200 != 0 {
            parts.push("O_CREAT");
        }
        if flags & 0x400 != 0 {
            parts.push("O_TRUNC");
        }
        if flags & 0x8 != 0 {
            parts.push("O_APPEND");
        }
        if flags & 0x800 != 0 {
            parts.push("O_EXCL");
        }
        if flags & 0x4 != 0 {
            parts.push("O_NONBLOCK");
        }
        if flags & 0x100000 != 0 {
            parts.push("O_DIRECTORY");
        }
        if flags & 0x1000000 != 0 {
            parts.push("O_CLOEXEC");
        }
    }

    if parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        parts.join("|")
    }
}

/// Format access() mode flags.
fn format_access_mode(mode: i32) -> String {
    if mode == 0 {
        return "F_OK".to_string();
    }

    let mut parts = Vec::new();
    if mode & 4 != 0 {
        parts.push("R_OK");
    }
    if mode & 2 != 0 {
        parts.push("W_OK");
    }
    if mode & 1 != 0 {
        parts.push("X_OK");
    }

    if parts.is_empty() {
        format!("{:#x}", mode)
    } else {
        parts.join("|")
    }
}

/// Format socket domain.
fn format_socket_domain(domain: i32) -> String {
    match domain {
        0 => "AF_UNSPEC".to_string(),
        1 => "AF_UNIX".to_string(),
        2 => "AF_INET".to_string(),
        #[cfg(target_os = "linux")]
        10 => "AF_INET6".to_string(),
        #[cfg(target_os = "macos")]
        30 => "AF_INET6".to_string(),
        _ => format!("domain={}", domain),
    }
}

/// Format socket type.
fn format_socket_type(sock_type: i32) -> String {
    // Mask out flags like SOCK_CLOEXEC, SOCK_NONBLOCK
    let base_type = sock_type & 0xf;
    let type_name = match base_type {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        5 => "SOCK_SEQPACKET",
        _ => return format!("type={}", sock_type),
    };

    #[cfg(target_os = "linux")]
    {
        let mut parts = vec![type_name];
        if sock_type & 0x80000 != 0 {
            parts.push("SOCK_CLOEXEC");
        }
        if sock_type & 0x800 != 0 {
            parts.push("SOCK_NONBLOCK");
        }
        parts.join("|")
    }

    #[cfg(not(target_os = "linux"))]
    {
        type_name.to_string()
    }
}

/// Format sockaddr structure.
fn format_sockaddr(addr_ptr: usize, _len: usize) -> Option<String> {
    if addr_ptr == 0 {
        return Some("NULL".to_string());
    }

    unsafe {
        // Read sa_family (first 2 bytes on most platforms)
        let family_ptr = addr_ptr as *const u16;
        let family = {
            #[cfg(target_os = "macos")]
            {
                // macOS has sa_len + sa_family, so family is second byte
                (*family_ptr >> 8) as i32
            }
            #[cfg(not(target_os = "macos"))]
            {
                *family_ptr as i32
            }
        };

        match family {
            2 => {
                // AF_INET - struct sockaddr_in
                let port = u16::from_be(*((addr_ptr + 2) as *const u16));
                let ip_bytes = std::slice::from_raw_parts((addr_ptr + 4) as *const u8, 4);
                Some(format!(
                    "{}.{}.{}.{}:{}",
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port
                ))
            }
            #[cfg(target_os = "linux")]
            10 => {
                // AF_INET6 on Linux
                let port = u16::from_be(*((addr_ptr + 2) as *const u16));
                Some(format!("[::]:{}]", port))
            }
            #[cfg(target_os = "macos")]
            30 => {
                // AF_INET6 on macOS
                let port = u16::from_be(*((addr_ptr + 2) as *const u16));
                Some(format!("[::]:{}]", port))
            }
            1 => {
                // AF_UNIX
                let path_ptr = (addr_ptr + 2) as *const c_char;
                if let Ok(s) = CStr::from_ptr(path_ptr).to_str() {
                    Some(format!("unix:{}", s))
                } else {
                    Some("unix:<invalid>".to_string())
                }
            }
            _ => Some(format!("family={}", family)),
        }
    }
}

/// Format dlopen flags.
fn format_dlopen_flags(flags: i32) -> String {
    let mut parts = Vec::new();

    // RTLD_LAZY vs RTLD_NOW
    if flags & 0x2 != 0 {
        parts.push("RTLD_NOW");
    } else if flags & 0x1 != 0 {
        parts.push("RTLD_LAZY");
    }

    // RTLD_GLOBAL vs RTLD_LOCAL
    #[cfg(target_os = "linux")]
    if flags & 0x100 != 0 {
        parts.push("RTLD_GLOBAL");
    }
    #[cfg(target_os = "macos")]
    if flags & 0x8 != 0 {
        parts.push("RTLD_GLOBAL");
    }

    if parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        parts.join("|")
    }
}

/// Format mmap protection flags.
fn format_mmap_prot(prot: i32) -> String {
    if prot == 0 {
        return "PROT_NONE".to_string();
    }

    let mut parts = Vec::new();
    if prot & 0x1 != 0 {
        parts.push("PROT_READ");
    }
    if prot & 0x2 != 0 {
        parts.push("PROT_WRITE");
    }
    if prot & 0x4 != 0 {
        parts.push("PROT_EXEC");
    }

    if parts.is_empty() {
        format!("{:#x}", prot)
    } else {
        parts.join("|")
    }
}

/// Format mmap flags.
fn format_mmap_flags(flags: i32) -> String {
    let mut parts = Vec::new();

    // MAP_SHARED vs MAP_PRIVATE
    if flags & 0x1 != 0 {
        parts.push("MAP_SHARED");
    } else if flags & 0x2 != 0 {
        parts.push("MAP_PRIVATE");
    }

    // Common flags
    #[cfg(target_os = "linux")]
    {
        if flags & 0x20 != 0 {
            parts.push("MAP_ANONYMOUS");
        }
        if flags & 0x10 != 0 {
            parts.push("MAP_FIXED");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if flags & 0x1000 != 0 {
            parts.push("MAP_ANON");
        }
        if flags & 0x10 != 0 {
            parts.push("MAP_FIXED");
        }
    }

    if parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        parts.join("|")
    }
}

/// Format fcntl command.
fn format_fcntl_cmd(cmd: i32) -> String {
    match cmd {
        0 => "F_DUPFD".to_string(),
        1 => "F_GETFD".to_string(),
        2 => "F_SETFD".to_string(),
        3 => "F_GETFL".to_string(),
        4 => "F_SETFL".to_string(),
        #[cfg(target_os = "linux")]
        1030 => "F_DUPFD_CLOEXEC".to_string(),
        #[cfg(target_os = "macos")]
        67 => "F_DUPFD_CLOEXEC".to_string(),
        _ => format!("cmd={}", cmd),
    }
}

/// Format shutdown() how argument.
fn format_shutdown_how(how: i32) -> String {
    match how {
        0 => "SHUT_RD".to_string(),
        1 => "SHUT_WR".to_string(),
        2 => "SHUT_RDWR".to_string(),
        _ => format!("how={}", how),
    }
}

/// Format lseek() whence argument.
fn format_seek_whence(whence: i32) -> String {
    match whence {
        0 => "SEEK_SET".to_string(),
        1 => "SEEK_CUR".to_string(),
        2 => "SEEK_END".to_string(),
        _ => format!("whence={}", whence),
    }
}

/// Format socket level (SOL_SOCKET, IPPROTO_TCP, etc.).
fn format_socket_level(level: i32) -> String {
    match level {
        0 => "IPPROTO_IP".to_string(),
        6 => "IPPROTO_TCP".to_string(),
        17 => "IPPROTO_UDP".to_string(),
        #[cfg(target_os = "linux")]
        1 => "SOL_SOCKET".to_string(),
        #[cfg(target_os = "macos")]
        0xffff => "SOL_SOCKET".to_string(),
        _ => format!("level={}", level),
    }
}

/// Format common socket options.
fn format_socket_optname(level: i32, optname: i32) -> String {
    // SOL_SOCKET options (level=1 on Linux, 0xffff on macOS)
    #[cfg(target_os = "linux")]
    let is_sol_socket = level == 1;
    #[cfg(target_os = "macos")]
    let is_sol_socket = level == 0xffff;

    if is_sol_socket {
        #[cfg(target_os = "linux")]
        {
            return match optname {
                2 => "SO_REUSEADDR".to_string(),
                15 => "SO_REUSEPORT".to_string(),
                5 => "SO_DONTROUTE".to_string(),
                6 => "SO_BROADCAST".to_string(),
                7 => "SO_SNDBUF".to_string(),
                8 => "SO_RCVBUF".to_string(),
                9 => "SO_KEEPALIVE".to_string(),
                13 => "SO_LINGER".to_string(),
                20 => "SO_RCVTIMEO".to_string(),
                21 => "SO_SNDTIMEO".to_string(),
                _ => format!("optname={}", optname),
            };
        }
        #[cfg(target_os = "macos")]
        {
            return match optname {
                0x0004 => "SO_REUSEADDR".to_string(),
                0x0200 => "SO_REUSEPORT".to_string(),
                0x0010 => "SO_DONTROUTE".to_string(),
                0x0020 => "SO_BROADCAST".to_string(),
                0x1001 => "SO_SNDBUF".to_string(),
                0x1002 => "SO_RCVBUF".to_string(),
                0x0008 => "SO_KEEPALIVE".to_string(),
                0x0080 => "SO_LINGER".to_string(),
                0x1006 => "SO_RCVTIMEO".to_string(),
                0x1005 => "SO_SNDTIMEO".to_string(),
                _ => format!("optname={}", optname),
            };
        }
    }

    // IPPROTO_TCP options
    if level == 6 {
        return match optname {
            1 => "TCP_NODELAY".to_string(),
            2 => "TCP_MAXSEG".to_string(),
            _ => format!("optname={}", optname),
        };
    }

    format!("optname={}", optname)
}

/// Format accept4() flags argument.
fn format_accept4_flags(flags: i32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    #[allow(unused_mut)]
    let mut parts: Vec<&str> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if flags & 0x80000 != 0 {
            parts.push("SOCK_CLOEXEC");
        }
        if flags & 0x800 != 0 {
            parts.push("SOCK_NONBLOCK");
        }
    }

    // Suppress unused variable warning on non-Linux platforms
    let _ = &parts;

    if parts.is_empty() {
        format!("flags={:#x}", flags)
    } else {
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(values: &[usize]) -> Vec<Argument> {
        values
            .iter()
            .map(|&v| Argument {
                raw_value: v,
                display: None,
            })
            .collect()
    }

    #[test]
    fn test_format_read() {
        let mut args = make_args(&[5, 0x12345678, 1024]);
        format_read(&mut args);

        assert_eq!(args[0].display, Some("fd=5".to_string()));
        assert_eq!(args[1].display, Some("buf=0x12345678".to_string()));
        assert_eq!(args[2].display, Some("count=1024".to_string()));
    }

    #[test]
    fn test_format_close() {
        let mut args = make_args(&[42]);
        format_close(&mut args);

        assert_eq!(args[0].display, Some("fd=42".to_string()));
    }

    #[test]
    fn test_format_open_flags() {
        // O_RDONLY
        assert!(format_open_flags(0).contains("O_RDONLY"));

        // O_WRONLY
        assert!(format_open_flags(1).contains("O_WRONLY"));

        // O_RDWR
        assert!(format_open_flags(2).contains("O_RDWR"));
    }

    #[test]
    fn test_format_access_mode() {
        assert_eq!(format_access_mode(0), "F_OK");
        assert!(format_access_mode(4).contains("R_OK"));
        assert!(format_access_mode(2).contains("W_OK"));
        assert!(format_access_mode(1).contains("X_OK"));
        assert!(format_access_mode(7).contains("R_OK"));
    }

    #[test]
    fn test_format_socket_domain() {
        assert_eq!(format_socket_domain(1), "AF_UNIX");
        assert_eq!(format_socket_domain(2), "AF_INET");
    }

    #[test]
    fn test_format_socket_type() {
        assert!(format_socket_type(1).contains("SOCK_STREAM"));
        assert!(format_socket_type(2).contains("SOCK_DGRAM"));
    }

    #[test]
    fn test_format_mmap_prot() {
        assert_eq!(format_mmap_prot(0), "PROT_NONE");
        assert!(format_mmap_prot(0x1).contains("PROT_READ"));
        assert!(format_mmap_prot(0x3).contains("PROT_READ"));
        assert!(format_mmap_prot(0x3).contains("PROT_WRITE"));
    }

    #[test]
    fn test_truncate() {
        // Uses shared truncate from tracing::format - max is total output length
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello..."); // 8 = 5 chars + 3 for "..."
    }

    // ========================================================================
    // Tests for new network functions
    // ========================================================================

    #[test]
    fn test_format_listen() {
        let mut args = make_args(&[3, 128]);
        format_listen(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("backlog=128".to_string()));
    }

    #[test]
    fn test_format_shutdown() {
        let mut args = make_args(&[3, 2]);
        format_shutdown(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("SHUT_RDWR".to_string()));
    }

    #[test]
    fn test_format_shutdown_how() {
        assert_eq!(format_shutdown_how(0), "SHUT_RD");
        assert_eq!(format_shutdown_how(1), "SHUT_WR");
        assert_eq!(format_shutdown_how(2), "SHUT_RDWR");
        assert_eq!(format_shutdown_how(99), "how=99");
    }

    #[test]
    fn test_format_send() {
        // Use NULL buffer (0) to avoid segfault from read_buffer_preview
        let mut args = make_args(&[3, 0, 128, 0]);
        format_send(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("buf=0x0".to_string()));
        assert_eq!(args[2].display, Some("len=128".to_string()));
        assert_eq!(args[3].display, Some("flags=0x0".to_string()));
    }

    #[test]
    fn test_format_send_with_data() {
        // Test with a real buffer
        let data = b"GET / HTTP/1.1\r\n";
        let mut args = make_args(&[3, data.as_ptr() as usize, data.len(), 0]);
        format_send(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("\"GET / HTTP/1.1\r\n\"".to_string()));
        assert_eq!(args[2].display, Some("len=16".to_string()));
        assert_eq!(args[3].display, Some("flags=0x0".to_string()));
    }

    #[test]
    fn test_format_recv() {
        let mut args = make_args(&[3, 0x12345678, 4096, 0]);
        format_recv(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("buf=0x12345678".to_string()));
        assert_eq!(args[2].display, Some("len=4096".to_string()));
        assert_eq!(args[3].display, Some("flags=0x0".to_string()));
    }

    #[test]
    fn test_format_getpeername() {
        let mut args = make_args(&[3, 0x12345678, 16]);
        format_getpeername(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("addr=0x12345678".to_string()));
        assert_eq!(args[2].display, Some("addrlen=16".to_string()));
    }

    // ========================================================================
    // Tests for new file I/O functions
    // ========================================================================

    #[test]
    fn test_format_pread() {
        let mut args = make_args(&[3, 0x12345678, 1024, 0]);
        format_pread(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("buf=0x12345678".to_string()));
        assert_eq!(args[2].display, Some("count=1024".to_string()));
        assert_eq!(args[3].display, Some("offset=0".to_string()));
    }

    #[test]
    fn test_format_lseek() {
        let mut args = make_args(&[3, 100, 0]);
        format_lseek(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("offset=100".to_string()));
        assert_eq!(args[2].display, Some("SEEK_SET".to_string()));
    }

    #[test]
    fn test_format_seek_whence() {
        assert_eq!(format_seek_whence(0), "SEEK_SET");
        assert_eq!(format_seek_whence(1), "SEEK_CUR");
        assert_eq!(format_seek_whence(2), "SEEK_END");
        assert_eq!(format_seek_whence(99), "whence=99");
    }

    #[test]
    fn test_format_ftruncate() {
        let mut args = make_args(&[3, 1024]);
        format_ftruncate(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("length=1024".to_string()));
    }

    #[test]
    fn test_format_fchmod() {
        let mut args = make_args(&[3, 0o644]);
        format_fchmod(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("mode=0o644".to_string()));
    }

    #[test]
    fn test_format_fchown() {
        let mut args = make_args(&[3, 501, 20]);
        format_fchown(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("owner=501".to_string()));
        assert_eq!(args[2].display, Some("group=20".to_string()));
    }

    // ========================================================================
    // Tests for new helper functions
    // ========================================================================

    #[test]
    fn test_format_socket_level() {
        assert_eq!(format_socket_level(0), "IPPROTO_IP");
        assert_eq!(format_socket_level(6), "IPPROTO_TCP");
        assert_eq!(format_socket_level(17), "IPPROTO_UDP");
        #[cfg(target_os = "linux")]
        assert_eq!(format_socket_level(1), "SOL_SOCKET");
        #[cfg(target_os = "macos")]
        assert_eq!(format_socket_level(0xffff), "SOL_SOCKET");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_socket_optname_linux() {
        assert_eq!(format_socket_optname(1, 2), "SO_REUSEADDR");
        assert_eq!(format_socket_optname(1, 15), "SO_REUSEPORT");
        assert_eq!(format_socket_optname(1, 9), "SO_KEEPALIVE");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_format_socket_optname_macos() {
        assert_eq!(format_socket_optname(0xffff, 0x0004), "SO_REUSEADDR");
        assert_eq!(format_socket_optname(0xffff, 0x0200), "SO_REUSEPORT");
        assert_eq!(format_socket_optname(0xffff, 0x0008), "SO_KEEPALIVE");
    }

    #[test]
    fn test_format_socket_optname_tcp() {
        assert_eq!(format_socket_optname(6, 1), "TCP_NODELAY");
        assert_eq!(format_socket_optname(6, 2), "TCP_MAXSEG");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_accept4_flags_linux() {
        assert_eq!(format_accept4_flags(0), "0");
        assert_eq!(format_accept4_flags(0x80000), "SOCK_CLOEXEC");
        assert_eq!(format_accept4_flags(0x800), "SOCK_NONBLOCK");
        assert_eq!(format_accept4_flags(0x80800), "SOCK_CLOEXEC|SOCK_NONBLOCK");
    }

    // ========================================================================
    // Additional network function tests
    // ========================================================================

    #[test]
    fn test_format_accept_null_addr() {
        let mut args = make_args(&[3, 0, 0]);
        format_accept(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("NULL".to_string()));
        assert_eq!(args[2].display, Some("addrlen=0".to_string()));
    }

    #[test]
    fn test_format_getsockname() {
        let mut args = make_args(&[5, 0xdeadbeef, 16]);
        format_getsockname(&mut args);

        assert_eq!(args[0].display, Some("fd=5".to_string()));
        assert_eq!(args[1].display, Some("addr=0xdeadbeef".to_string()));
        assert_eq!(args[2].display, Some("addrlen=16".to_string()));
    }

    #[test]
    fn test_format_getsockopt() {
        #[cfg(target_os = "linux")]
        let level = 1; // SOL_SOCKET on Linux
        #[cfg(target_os = "macos")]
        let level = 0xffff; // SOL_SOCKET on macOS

        #[cfg(target_os = "linux")]
        let optname = 2; // SO_REUSEADDR on Linux
        #[cfg(target_os = "macos")]
        let optname = 0x0004; // SO_REUSEADDR on macOS

        let mut args = make_args(&[3, level, optname, 0x1000, 0x1004]);
        format_getsockopt(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("SOL_SOCKET".to_string()));
        assert_eq!(args[2].display, Some("SO_REUSEADDR".to_string()));
        assert_eq!(args[3].display, Some("optval=0x1000".to_string()));
        assert_eq!(args[4].display, Some("optlen=0x1004".to_string()));
    }

    #[test]
    fn test_format_setsockopt() {
        #[cfg(target_os = "linux")]
        let level = 1;
        #[cfg(target_os = "macos")]
        let level = 0xffff;

        #[cfg(target_os = "linux")]
        let optname = 9; // SO_KEEPALIVE on Linux
        #[cfg(target_os = "macos")]
        let optname = 0x0008; // SO_KEEPALIVE on macOS

        let mut args = make_args(&[4, level, optname, 0x2000, 4]);
        format_setsockopt(&mut args);

        assert_eq!(args[0].display, Some("fd=4".to_string()));
        assert_eq!(args[1].display, Some("SOL_SOCKET".to_string()));
        assert_eq!(args[2].display, Some("SO_KEEPALIVE".to_string()));
        assert_eq!(args[3].display, Some("optval=0x2000".to_string()));
        assert_eq!(args[4].display, Some("optlen=4".to_string()));
    }

    #[test]
    fn test_format_recv_with_flags() {
        let mut args = make_args(&[3, 0x12345678, 1024, 0x40]); // MSG_DONTWAIT = 0x40
        format_recv(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("buf=0x12345678".to_string()));
        assert_eq!(args[2].display, Some("len=1024".to_string()));
        assert_eq!(args[3].display, Some("flags=0x40".to_string()));
    }

    // ========================================================================
    // Additional file I/O tests
    // ========================================================================

    #[test]
    fn test_format_pwrite_null_buf() {
        let mut args = make_args(&[3, 0, 100, 512]);
        format_pwrite(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("buf=0x0".to_string()));
        assert_eq!(args[2].display, Some("count=100".to_string()));
        assert_eq!(args[3].display, Some("offset=512".to_string()));
    }

    #[test]
    fn test_format_pwrite_with_data() {
        let data = b"Hello, World!";
        let mut args = make_args(&[3, data.as_ptr() as usize, data.len(), 1024]);
        format_pwrite(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("\"Hello, World!\"".to_string()));
        assert_eq!(args[2].display, Some("count=13".to_string()));
        assert_eq!(args[3].display, Some("offset=1024".to_string()));
    }

    #[test]
    fn test_format_pread_with_offset() {
        let mut args = make_args(&[5, 0xabcd0000, 4096, 8192]);
        format_pread(&mut args);

        assert_eq!(args[0].display, Some("fd=5".to_string()));
        assert_eq!(args[1].display, Some("buf=0xabcd0000".to_string()));
        assert_eq!(args[2].display, Some("count=4096".to_string()));
        assert_eq!(args[3].display, Some("offset=8192".to_string()));
    }

    #[test]
    fn test_format_lseek_seek_cur() {
        let mut args = make_args(&[3, 0, 1]); // offset=0, SEEK_CUR
        format_lseek(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("offset=0".to_string()));
        assert_eq!(args[2].display, Some("SEEK_CUR".to_string()));
    }

    #[test]
    fn test_format_lseek_seek_end() {
        // Test negative offset with SEEK_END
        let offset = (-100i64) as usize;
        let mut args = make_args(&[3, offset, 2]); // SEEK_END
        format_lseek(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("offset=-100".to_string()));
        assert_eq!(args[2].display, Some("SEEK_END".to_string()));
    }

    #[test]
    fn test_format_fchmod_executable() {
        let mut args = make_args(&[3, 0o755]);
        format_fchmod(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("mode=0o755".to_string()));
    }

    #[test]
    fn test_format_fchown_root() {
        let mut args = make_args(&[3, 0, 0]); // root:root
        format_fchown(&mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("owner=0".to_string()));
        assert_eq!(args[2].display, Some("group=0".to_string()));
    }

    // ========================================================================
    // Integration tests via format_native_arguments
    // ========================================================================

    #[test]
    fn test_format_native_arguments_listen() {
        let mut args = make_args(&[3, 128]);
        format_native_arguments("listen", &mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("backlog=128".to_string()));
    }

    #[test]
    fn test_format_native_arguments_listen_underscore() {
        let mut args = make_args(&[4, 64]);
        format_native_arguments("_listen", &mut args);

        assert_eq!(args[0].display, Some("fd=4".to_string()));
        assert_eq!(args[1].display, Some("backlog=64".to_string()));
    }

    #[test]
    fn test_format_native_arguments_shutdown() {
        let mut args = make_args(&[5, 1]);
        format_native_arguments("shutdown", &mut args);

        assert_eq!(args[0].display, Some("fd=5".to_string()));
        assert_eq!(args[1].display, Some("SHUT_WR".to_string()));
    }

    #[test]
    fn test_format_native_arguments_lseek64() {
        let mut args = make_args(&[3, 0, 0]);
        format_native_arguments("lseek64", &mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[2].display, Some("SEEK_SET".to_string()));
    }

    #[test]
    fn test_format_native_arguments_fsync() {
        let mut args = make_args(&[7]);
        format_native_arguments("fsync", &mut args);

        assert_eq!(args[0].display, Some("fd=7".to_string()));
    }

    #[test]
    fn test_format_native_arguments_fdatasync() {
        let mut args = make_args(&[8]);
        format_native_arguments("fdatasync", &mut args);

        assert_eq!(args[0].display, Some("fd=8".to_string()));
    }

    #[test]
    fn test_format_native_arguments_fchdir() {
        let mut args = make_args(&[9]);
        format_native_arguments("fchdir", &mut args);

        assert_eq!(args[0].display, Some("fd=9".to_string()));
    }

    #[test]
    fn test_format_native_arguments_ftruncate64() {
        let mut args = make_args(&[3, 2048]);
        format_native_arguments("ftruncate64", &mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[1].display, Some("length=2048".to_string()));
    }

    #[test]
    fn test_format_native_arguments_pread64() {
        let mut args = make_args(&[3, 0x1000, 512, 0]);
        format_native_arguments("pread64", &mut args);

        assert_eq!(args[0].display, Some("fd=3".to_string()));
        assert_eq!(args[2].display, Some("count=512".to_string()));
    }

    #[test]
    fn test_format_native_arguments_unknown() {
        let mut args = make_args(&[1, 2, 3]);
        format_native_arguments("unknown_syscall", &mut args);

        // Unknown functions should leave display as None
        assert_eq!(args[0].display, None);
        assert_eq!(args[1].display, None);
        assert_eq!(args[2].display, None);
    }

    // ========================================================================
    // Edge case tests
    // ========================================================================

    #[test]
    fn test_format_listen_empty_args() {
        let mut args: Vec<Argument> = vec![];
        format_listen(&mut args);
        // Should not panic with empty args
    }

    #[test]
    fn test_format_shutdown_insufficient_args() {
        let mut args = make_args(&[3]); // Missing 'how' arg
        format_shutdown(&mut args);
        // Should not panic, just not format anything
        assert_eq!(args[0].display, None);
    }

    #[test]
    fn test_format_getsockopt_insufficient_args() {
        let mut args = make_args(&[3, 1, 2]); // Missing optval and optlen
        format_getsockopt(&mut args);
        // Should not format since we need 5 args
        assert_eq!(args[0].display, None);
    }

    #[test]
    fn test_format_socket_optname_unknown_level() {
        // Test with unknown socket level
        assert_eq!(format_socket_optname(999, 1), "optname=1");
    }

    #[test]
    fn test_format_socket_level_unknown() {
        assert_eq!(format_socket_level(999), "level=999");
    }

    // ========================================================================
    // DNS resolution function tests
    // ========================================================================

    #[test]
    fn test_format_getaddrinfo() {
        let host = std::ffi::CString::new("pypi.org").unwrap();
        let svc = std::ffi::CString::new("443").unwrap();
        let mut args = make_args(&[
            host.as_ptr() as usize,
            svc.as_ptr() as usize,
            0x1000,
            0x2000,
        ]);
        format_getaddrinfo(&mut args);

        assert_eq!(args[0].display, Some("\"pypi.org\"".to_string()));
        assert_eq!(args[1].display, Some("\"443\"".to_string()));
        assert_eq!(args[2].display, Some("hints=0x1000".to_string()));
        assert_eq!(args[3].display, Some("res=0x2000".to_string()));
    }

    #[test]
    fn test_format_getaddrinfo_null_node() {
        let svc = std::ffi::CString::new("80").unwrap();
        let mut args = make_args(&[0, svc.as_ptr() as usize, 0, 0]);
        format_getaddrinfo(&mut args);

        assert_eq!(args[0].display, Some("NULL".to_string()));
        assert_eq!(args[1].display, Some("\"80\"".to_string()));
    }

    #[test]
    fn test_format_gethostbyname2() {
        let host = std::ffi::CString::new("example.com").unwrap();
        let mut args = make_args(&[host.as_ptr() as usize, 2]); // AF_INET
        format_gethostbyname2(&mut args);

        assert_eq!(args[0].display, Some("\"example.com\"".to_string()));
        assert_eq!(args[1].display, Some("AF_INET".to_string()));
    }

    #[test]
    fn test_format_native_arguments_getaddrinfo() {
        let host = std::ffi::CString::new("registry.npmjs.org").unwrap();
        let svc = std::ffi::CString::new("https").unwrap();
        let mut args = make_args(&[host.as_ptr() as usize, svc.as_ptr() as usize, 0, 0]);
        format_native_arguments("getaddrinfo", &mut args);

        assert_eq!(args[0].display, Some("\"registry.npmjs.org\"".to_string()));
        assert_eq!(args[1].display, Some("\"https\"".to_string()));
    }

    #[test]
    fn test_format_native_arguments_gethostbyname() {
        let host = std::ffi::CString::new("evil.com").unwrap();
        let mut args = make_args(&[host.as_ptr() as usize]);
        format_native_arguments("gethostbyname", &mut args);

        assert_eq!(args[0].display, Some("\"evil.com\"".to_string()));
    }
}
