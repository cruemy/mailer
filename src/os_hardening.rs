pub fn apply_process_hardening() {
    disable_core_dumps();
    disable_ptrace_dumping();
}

#[cfg(unix)]
fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to disable core dumps");
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

#[cfg(target_os = "linux")]
fn disable_ptrace_dumping() {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to disable process dumpability");
    }
}

#[cfg(not(target_os = "linux"))]
fn disable_ptrace_dumping() {}
