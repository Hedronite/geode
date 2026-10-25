//! Cargo-built pin fixture. Not a supported `geode` command.
//!
//! `pinned_matching_command_runs` pins this binary instead of a copy of
//! `/bin/sh`. Apple launch constraints kill a relocated platform binary
//! (`com.apple.sh`) with SIGKILL. This binary is not a platform image, so
//! macOS will exec it. Invoked as `-c "printf ok"`, it prints `ok`.

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let second = args.next();
    if first.as_deref() == Some("-c")
        && second.as_deref() == Some("printf ok")
        && args.next().is_none()
    {
        print!("ok");
        return;
    }
    std::process::exit(2);
}
