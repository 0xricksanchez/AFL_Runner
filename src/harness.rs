use std::fs;
use std::path::PathBuf;

/// Represents a harness configuration
#[derive(Debug)]
pub struct Harness {
    /// Instrumented and maybe `AFL_HARDEN=1`
    pub target_binary: PathBuf,
    /// `AFL_USE_*SAN=1`
    pub sanitizer_binary: Option<PathBuf>,
    /// `AFL_LLVM_CMPLOG=1`
    pub cmplog_binary: Option<PathBuf>,
    /// `AFL_LLVM_LAF_ALL=1`
    pub cmpcov_binary: Option<PathBuf>,
    /// Additional arguments for the harness
    /// If the harness reads from stdin, use @@ as placeholder
    pub target_args: Option<String>,
}

impl Harness {
    /// Creates a new `Harness` instance
    ///
    /// # Arguments
    ///
    /// * `target_binary` - Path to the target binary
    /// * `sanitizer_binary` - Optional path to the sanitizer binary
    /// * `cmplog_binary` - Optional path to the CMPLOG binary
    /// * `cmpcov_binary` - Optional path to the CMPCOV binary
    /// * `target_args` - Optional additional arguments for the harness
    ///
    /// # Panics
    ///
    /// Panics if the target binary is not found
    pub fn new(
        target_binary: PathBuf,
        sanitizer_binary: Option<PathBuf>,
        cmplog_binary: Option<PathBuf>,
        cmpcov_binary: Option<PathBuf>,
        target_args: Option<String>,
    ) -> Self {
        let target_binary = Self::get_target_binary(target_binary);
        assert!(target_binary.is_some(), "Could not find target binary");

        let sanitizer_binary = Self::get_binary(sanitizer_binary);
        let cmplog_binary = Self::get_binary(cmplog_binary);
        let cmpcov_binary = Self::get_binary(cmpcov_binary);
        Self {
            target_binary: target_binary.unwrap(),
            sanitizer_binary,
            cmplog_binary,
            cmpcov_binary,
            target_args,
        }
    }

    /// Checks if the given path is a binary file
    ///
    /// # Arguments
    ///
    /// * `path` - The path to check
    fn is_path_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(path: &P) -> bool {
        let path: PathBuf = path.into();
        path.exists() && path.is_file()
    }

    /// Resolves the path to a binary file
    ///
    /// # Arguments
    ///
    /// * `binary` - Optional path to the binary file
    fn get_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(
        binary: Option<P>,
    ) -> Option<PathBuf> {
        let binary = binary.map_or_else(PathBuf::new, std::convert::Into::into);
        if Self::is_path_binary(&binary) {
            let resolved_bin = fs::canonicalize(binary).expect("Failed to resolve path");
            return Some(resolved_bin);
        }
        None
    }

    /// Resolves the path to the target binary
    ///
    /// # Arguments
    ///
    /// * `target_binary` - Path to the target binary
    fn get_target_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(
        target_binary: P,
    ) -> Option<PathBuf> {
        let target_binary = target_binary.into();
        if Self::is_path_binary(&target_binary) {
            let resolved_tbin = fs::canonicalize(target_binary).expect("Failed to resolve path");
            return Some(resolved_tbin);
        }
        None
    }
}
