use std::io;
use std::process::Command;

/// Get possible tmux session names for completion
fn get_session_names() -> io::Result<Vec<String>> {
    let output = Command::new("tmux").arg("ls").output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split(':').next())
            .map(|s| s.trim().to_string())
            .collect())
    } else {
        Ok(vec![])
    }
}

/// Value parser function that takes the required argument
pub fn possible_values_session_names(s: &str) -> Result<String, String> {
    match get_session_names() {
        Ok(names) => {
            if names.is_empty() {
                return Err("No active tmux sessions found".to_string());
            }
            if names.contains(&s.to_string()) {
                Ok(s.to_string())
            } else {
                Err(format!("Available sessions: {}", names.join(", ")))
            }
        }
        Err(_) => Err("Failed to get tmux sessions".to_string()),
    }
}
