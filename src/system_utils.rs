use std::{
    fs,
    io::{self, stdin, Read},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use sysinfo::System;
use uuid::Uuid;

/// Retrieves the amount of free memory in the system in MB
/// This function is used to determine the `AFL_TESTCACHE_SIZE` value
///
/// NOTE: This function will likely break on Windows
pub fn get_free_mem_in_mb() -> u64 {
    let s = System::new_all();
    s.free_memory() / 1024 / 1024
}

pub fn create_ramdisk() -> Result<String> {
    println!("[*] Attempting to create RAMDisk. Needing elevated privileges.");
    let uuid = Uuid::new_v4().to_string();
    let folder = format!("/tmp/tmpfs/{uuid}");
    fs::create_dir_all(&folder)?;
    let _ = Command::new("sudo")
        .args(["mount", "-o", "size=4G", "-t", "tmpfs", "none"])
        .arg(&folder)
        .output()?;
    Ok(folder)
}

/// Validates if a path points to the AFL binary
#[inline]
fn is_valid_afl_binary(path: &Path) -> bool {
    path.exists() && path.is_file() && path.ends_with("afl-fuzz")
}

/// Retrieves the path to the AFL binary
pub fn find_binary_in_path<P>(custom_path: Option<P>) -> Result<PathBuf>
where
    P: Into<PathBuf>,
{
    // Check custom path
    if let Some(path) = custom_path
        .map(Into::into)
        .filter(|p: &PathBuf| is_valid_afl_binary(p))
    {
        return Ok(path);
    }

    // Check AFL_PATH environment variable
    if let Some(path) = std::env::var("AFL_PATH")
        .map(PathBuf::from)
        .ok()
        .filter(|p: &PathBuf| is_valid_afl_binary(p))
    {
        return Ok(path);
    }

    // Try to find using 'which'
    let path = Command::new("which")
        .arg("afl-fuzz")
        .output()
        .context("Failed to execute 'which'")?;

    if path.status.success() {
        let path_str = String::from_utf8_lossy(&path.stdout).trim().to_string();
        let path_buf = PathBuf::from(path_str);

        if is_valid_afl_binary(&path_buf) {
            return Ok(path_buf);
        }
    }

    anyhow::bail!("Could not find afl-fuzz binary")
}

/// Helper function for creating directories
///
/// # Arguments
///
/// * `dir` - The directory path to create
/// * `check_empty` - If true, checks if directory is empty and prompts for cleanup
///
/// # Returns
///
/// * `Result<()>` - Ok if directory was created/cleaned successfully, Error otherwise
pub fn mkdir_helper(dir: &Path, check_empty: bool) -> Result<()> {
    if dir.is_file() {
        bail!("Path {} exists but is a file", dir.display());
    }

    if check_empty && dir.exists() {
        let is_empty = is_directory_empty(dir)?;
        if !is_empty && should_clean_directory(dir)? {
            fs::remove_dir_all(dir)?;
        }
    }

    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    Ok(())
}

/// Checks if a directory is empty
#[inline]
fn is_directory_empty(dir: &Path) -> io::Result<bool> {
    Ok(dir.read_dir()?.next().is_none())
}

/// Prompts user whether to clean a non-empty directory
fn should_clean_directory(dir: &Path) -> io::Result<bool> {
    println!("Directory {} is not empty. Clean it [Y/n]? ", dir.display());

    let mut input = String::with_capacity(4); // Small capacity for single char + newline
    stdin().read_line(&mut input)?;

    Ok(matches!(
        input.trim().to_lowercase().chars().next().unwrap_or('y'),
        'y' | '\n'
    ))
}

/// Gets user input from stdin
pub fn get_user_input() -> char {
    std::io::stdin()
        .bytes()
        .next()
        .and_then(std::result::Result::ok)
        .map_or('y', |byte| {
            let b = byte as char;
            if b.is_ascii_alphabetic() {
                b.to_lowercase().next().unwrap()
            } else if b == '\n' {
                'y'
            } else {
                b
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_find_binary_custom_path() {
        let dir = tempdir().unwrap();
        let bin_path = dir.path().join("afl-fuzz");
        File::create(&bin_path).unwrap();

        let result = find_binary_in_path(Some(bin_path.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), bin_path);
    }

    #[test]
    fn test_find_binary_env_var() {
        let dir = tempdir().unwrap();
        let bin_path = dir.path().join("afl-fuzz");
        File::create(&bin_path).unwrap();

        env::set_var("AFL_PATH", bin_path.to_str().unwrap());
        let result = find_binary_in_path::<PathBuf>(None);
        assert!(result.is_ok());
        env::remove_var("AFL_PATH");
    }

    #[test]
    fn test_mkdir_new_directory() -> Result<()> {
        let temp = tempdir()?;
        let new_dir = temp.path().join("new_dir");

        mkdir_helper(&new_dir, false)?;
        assert!(new_dir.exists());
        assert!(new_dir.is_dir());

        Ok(())
    }

    #[test]
    fn test_mkdir_existing_file() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("file");
        File::create(&file_path).unwrap();

        let result = mkdir_helper(&file_path, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_directory_empty() -> io::Result<()> {
        let temp = tempdir()?;

        // Empty directory
        assert!(is_directory_empty(temp.path())?);

        // Non-empty directory
        File::create(temp.path().join("file"))?;
        assert!(!is_directory_empty(temp.path())?);

        Ok(())
    }
}
