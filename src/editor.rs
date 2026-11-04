// ported from neboto-tui src/editor.rs @ d483900
use crate::error::{Error, Result};
use std::env;
use std::io::Write;
use std::process::Command;

/// Spawn an editor with arbitrary text content — the single editor entry
/// point (what to open is decided in `App::open_in_editor`).
/// The `suffix` hint (e.g. ".yaml", ".json") sets the temp file extension so the
/// editor can pick the right syntax highlighting.
pub fn spawn_editor_with_content(content: &str, suffix: &str) -> Result<()> {
    let mut temp_file = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .map_err(|e| Error::EditorFailed(format!("Failed to create temp file: {}", e)))?;

    temp_file
        .write_all(content.as_bytes())
        .map_err(|e| Error::EditorFailed(format!("Failed to write to temp file: {}", e)))?;

    temp_file
        .flush()
        .map_err(|e| Error::EditorFailed(format!("Failed to flush temp file: {}", e)))?;

    let (editor, args) = get_editor_command()?;
    spawn_editor(&editor, &args, temp_file.path().to_str().unwrap())?;
    Ok(())
}

/// The editor to use when `$EDITOR` is unset.
fn default_editor(windows: bool) -> &'static str {
    if windows {
        "notepad"
    } else {
        "vim"
    }
}

/// Get the editor command from $EDITOR, or the platform default.
/// Returns (program, args) tuple where args can contain multiple arguments
fn get_editor_command() -> Result<(String, Vec<String>)> {
    let editor_str = env::var("EDITOR").unwrap_or_default();
    Ok(editor_command(&editor_str, cfg!(windows)))
}

fn editor_command(editor_str: &str, windows: bool) -> (String, Vec<String>) {
    let mut parts = split_command(editor_str);
    if parts.is_empty() {
        return (default_editor(windows).to_string(), vec![]);
    }
    let program = parts.remove(0);
    (program, parts)
}

/// Split a command line on whitespace, honouring simple single and double
/// quotes (`"C:\Program Files\Code\code.cmd" --wait`). No escapes: a
/// backslash is a path separator, not an escape.
fn split_command(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_token = true;
            }
            None if c.is_whitespace() => {
                if in_token {
                    out.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            None => {
                cur.push(c);
                in_token = true;
            }
        }
    }
    if in_token {
        out.push(cur);
    }
    out
}

/// The programs to try, in order. On Windows a bare name (VS Code's
/// `code`) is usually a `.cmd` shim, which `Command` won't find on its own
/// (it only appends `.exe`), so the shim names follow. A `.cmd` / `.bat` is
/// run directly: std quotes its arguments for `cmd.exe` itself, which a
/// hand-built `cmd /C` line gets wrong once a path has spaces in it.
fn candidates(program: &str, windows: bool) -> Vec<String> {
    let has_extension = std::path::Path::new(program).extension().is_some();
    if windows && !has_extension {
        vec![program.to_string(), format!("{program}.cmd"), format!("{program}.bat")]
    } else {
        vec![program.to_string()]
    }
}

/// Spawn the editor process and wait for it to complete
fn spawn_editor(editor: &str, args: &[String], file_path: &str) -> Result<()> {
    use std::process::Stdio;

    let mut status = None;
    for program in candidates(editor, cfg!(windows)) {
        // Launch editor with inherited stdio, the file path last
        let mut cmd = Command::new(program);
        cmd.args(args).arg(file_path);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        match cmd.status() {
            Ok(s) => {
                status = Some(s);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::EditorFailed(format!("Failed to spawn editor: {}", e))),
        }
    }
    let status = status.ok_or_else(|| Error::EditorNotFound(editor.to_string()))?;

    if !status.success() {
        return Err(Error::EditorFailed(format!(
            "Editor exited with non-zero status: {}",
            status
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_plain_and_quoted() {
        assert_eq!(split_command("vim"), v(&["vim"]));
        assert_eq!(split_command("code --wait  -n"), v(&["code", "--wait", "-n"]));
        assert_eq!(
            split_command(r#""C:\Program Files\Microsoft VS Code\bin\code.cmd" --wait"#),
            v(&[r"C:\Program Files\Microsoft VS Code\bin\code.cmd", "--wait"])
        );
        assert_eq!(split_command("'/opt/my ed/ed' -x"), v(&["/opt/my ed/ed", "-x"]));
        assert_eq!(split_command(r#"ed "" x"#), v(&["ed", "", "x"]));
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn default_editor_per_platform() {
        assert_eq!(editor_command("", false), ("vim".into(), vec![]));
        assert_eq!(editor_command("  ", true), ("notepad".into(), vec![]));
        assert_eq!(editor_command("nvim -R", false), ("nvim".into(), v(&["-R"])));
    }

    #[test]
    fn windows_tries_the_shims_after_a_bare_name() {
        assert_eq!(candidates("code", true), v(&["code", "code.cmd", "code.bat"]));
        assert_eq!(
            candidates(r"C:\Program Files\Microsoft VS Code\bin\code.cmd", true),
            v(&[r"C:\Program Files\Microsoft VS Code\bin\code.cmd"])
        );
        assert_eq!(candidates("NOTEPAD.EXE", true), v(&["NOTEPAD.EXE"]));
        assert_eq!(candidates("code", false), v(&["code"]));
    }
}
