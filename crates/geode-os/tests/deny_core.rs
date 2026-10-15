//! Abort after [`geode_os::deny_core_dumps`] and assert no core file.
//!
//! The re-exec is the test harness, not a user-child spawn API.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn abort_after_deny_core_dumps_leaves_no_core() {
    if std::env::var_os("GEODE_OS_ABORT_CHILD").is_some() {
        geode_os::deny_core_dumps().expect("deny_core_dumps");
        let mut note = String::new();
        // SAFETY: getrlimit writes into a zeroed libc::rlimit we own.
        let cur = unsafe {
            let mut lim = std::mem::zeroed::<libc::rlimit>();
            if libc::getrlimit(libc::RLIMIT_CORE, &mut lim) != 0 {
                panic!("{}", std::io::Error::last_os_error());
            }
            lim.rlim_cur
        };
        note.push_str(&format!("rlim_cur={cur}\n"));
        #[cfg(target_os = "linux")]
        {
            let status = fs::read_to_string("/proc/self/status").expect("proc status");
            let line = status
                .lines()
                .find(|l| l.starts_with("Dumpable:"))
                .expect("Dumpable line");
            note.push_str(line);
            note.push('\n');
        }
        let path = std::env::var("GEODE_OS_STATUS").expect("status path");
        fs::write(&path, note).expect("write status");
        let _ = fs::File::open(&path).and_then(|f| f.sync_all());
        std::process::abort();
    }

    let dir = std::env::temp_dir().join(format!(
        "geode-os-core-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    let status_path = dir.join("status");
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(&exe)
        .current_dir(&dir)
        .env("GEODE_OS_ABORT_CHILD", "1")
        .env("GEODE_OS_STATUS", &status_path)
        .args([
            "--exact",
            "abort_after_deny_core_dumps_leaves_no_core",
            "--test-threads=1",
        ])
        .spawn()
        .expect("spawn abort child");
    let pid = child.id();
    let status = child.wait().expect("wait abort child");
    assert!(!status.success(), "abort child exited cleanly: {status:?}");
    let note = fs::read_to_string(&status_path).expect("status file");
    assert!(
        note.contains("rlim_cur=0"),
        "RLIMIT_CORE was not cleared: {note}"
    );
    #[cfg(target_os = "linux")]
    {
        let dumpable = note
            .lines()
            .find(|l| l.starts_with("Dumpable:"))
            .expect("Dumpable line");
        assert!(
            dumpable.trim_end().ends_with('0'),
            "dumpable was not 0: {dumpable}"
        );
    }
    assert_no_core(&dir, pid);
    let _ = fs::remove_dir_all(&dir);
}

fn assert_no_core(dir: &Path, pid: u32) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(!name.starts_with("core"), "core file in temp dir: {name}");
        }
    }
    let cores = format!("/cores/core.{pid}");
    assert!(!Path::new(&cores).exists(), "core file left at {cores}");
}
