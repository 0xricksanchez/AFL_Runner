use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Error type for harness operations
#[derive(Debug, Clone)]
pub enum HarnessError {
    /// Binary file not found or invalid
    InvalidBinary(PathBuf),
    /// Path resolution failed
    PathResolution(PathBuf, String), // Changed to String to make it Clone}
    /// Nyx mode feature not supported
    NyxModeFeature(String),
    /// Nyx mode share directory not found or invalid
    NyxModeShareDir,
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinary(path) => write!(f, "Invalid binary path: {}", path.display()),
            Self::PathResolution(path, err) => {
                write!(f, "Failed to resolve path {}: {}", path.display(), err)
            }
            Self::NyxModeFeature(feature) => {
                write!(f, "Feature not supported in Nyx mode: {}", feature)
            }
            Self::NyxModeShareDir => {
                write!(
                    f,
                    "Target is not a nyx share directory or the directory does not exist"
                )
            }
        }
    }
}

impl Error for HarnessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Represents a harness configuration for AFL++ fuzzing
#[derive(Debug, Clone)]
pub struct Harness {
    /// Instrumented and maybe `AFL_HARDEN=1`
    pub target_bin: PathBuf,
    /// `AFL_USE_*SAN=1`
    pub sanitizer_bin: Option<PathBuf>,
    /// `AFL_LLVM_CMPLOG=1`
    pub cmplog_bin: Option<PathBuf>,
    /// `AFL_LLVM_LAF_ALL=1`
    pub cmpcov_bin: Option<PathBuf>,
    /// Code-coverage instrumented binary
    pub cov_bin: Option<PathBuf>,
    /// Additional arguments for the harness
    /// If the harness reads from stdin, use @@ as placeholder
    pub target_args: Option<String>,
    /// Nyx mode (`-Y`)
    pub nyx_mode: bool,
}

impl Harness {
    /// Creates a new `Harness` instance
    ///
    /// # Arguments
    ///
    /// * `target_binary` - Path to the target binary
    /// * `target_args` - Optional vector of arguments for the harness
    /// * `nyx_mode` - Nyx mode (`-Y`)
    ///
    /// # Errors
    ///
    /// Returns `HarnessError` if the target binary is invalid or cannot be resolved
    pub fn new<P: AsRef<Path>>(
        target_binary: P,
        target_args: Option<Vec<String>>,
        nyx_mode: bool,
    ) -> Result<Self, HarnessError> {
        let target_bin = Self::resolve_binary(target_binary.as_ref(), nyx_mode)?;
        let target_args = target_args.map(|args| args.join(" "));

        Ok(Self {
            target_bin,
            sanitizer_bin: None,
            cmplog_bin: None,
            cmpcov_bin: None,
            cov_bin: None,
            target_args,
            nyx_mode,
        })
    }

    /// Helper method to process optional binary paths
    fn process_optional_binary<P>(
        binary: Option<P>,
        nyx_mode: bool,
    ) -> Result<Option<PathBuf>, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        binary
            .map(|b| Self::resolve_binary(b, nyx_mode))
            .transpose()
    }

    /// Sets the sanitizer binary
    ///
    /// # Errors
    /// Returns `HarnessError` if the binary is invalid or cannot be resolved
    pub fn with_sanitizer<P>(mut self, sanitizer_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.sanitizer_bin = Self::process_optional_binary(sanitizer_bin, self.nyx_mode)?;
        Ok(self)
    }

    /// Sets the cmplog binary
    ///
    /// # Errors
    /// Returns `HarnessError` if the binary is invalid or cannot be resolved
    pub fn with_cmplog<P>(mut self, cmplog_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        if cmplog_bin.is_some() && self.nyx_mode {
            return Err(HarnessError::NyxModeFeature("cmplog".to_string()));
        }
        self.cmplog_bin = Self::process_optional_binary(cmplog_bin, self.nyx_mode)?;
        Ok(self)
    }

    /// Sets the cmpcov binary
    ///
    /// # Errors
    /// Returns `HarnessError` if the binary is invalid or cannot be resolved
    pub fn with_cmpcov<P>(mut self, cmpcov_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.cmpcov_bin = Self::process_optional_binary(cmpcov_bin, self.nyx_mode)?;
        Ok(self)
    }

    /// Sets the code-coverage binary
    ///
    /// # Errors
    /// Returns `HarnessError` if the binary is invalid or cannot be resolved
    pub fn with_coverage<P>(mut self, cov_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        if cov_bin.is_some() && self.nyx_mode {
            return Err(HarnessError::NyxModeFeature("coverage".to_string()));
        }
        self.cov_bin = Self::process_optional_binary(cov_bin, self.nyx_mode)?;
        Ok(self)
    }

    /// Resolves a binary path to its canonical form
    ///
    /// # Arguments
    ///
    /// * `binary` - Path to the binary to resolve
    /// * `nyx_mode` - Nyx mode (`-Y`)
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf, HarnessError>` - Canonical path if successful
    fn resolve_binary<P>(binary: P, nyx_mode: bool) -> Result<PathBuf, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        // Convert once to PathBuf to avoid multiple conversions
        let binary_path = binary.into();

        if nyx_mode {
            if !binary_path.is_dir() || !binary_path.exists() {
                return Err(HarnessError::NyxModeShareDir);
            }
        } else if !binary_path.is_file() {
            return Err(HarnessError::InvalidBinary(binary_path));
        }

        fs::canonicalize(&binary_path)
            .map_err(|e| HarnessError::PathResolution(binary_path, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    // Added test helper
    fn create_test_binary(dir: &Path, name: &str) -> PathBuf {
        let bin_path = dir.join(name);
        File::create(&bin_path).unwrap();
        bin_path
    }

    #[test]
    fn test_harness_creation() {
        let dir = tempdir().unwrap();
        let bin_path = create_test_binary(dir.path(), "test_binary");
        File::create(&bin_path).unwrap();
        let target_args = vec!["--arg1".to_string(), "--arg2".to_string()];

        let harness = Harness::new(&bin_path, Some(target_args), false).unwrap();
        assert_eq!(harness.target_bin, fs::canonicalize(&bin_path).unwrap());
        assert_eq!(harness.target_args, Some(("--arg1 --arg2").to_string()));
    }

    #[test]
    fn test_invalid_binary() {
        let non_existent = PathBuf::from("/nonexistent/binary");
        assert!(matches!(
            Harness::new(&non_existent, None, false),
            Err(HarnessError::InvalidBinary(_))
        ));
    }

    #[test]
    fn test_getters() -> Result<(), HarnessError> {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");
        let san_bin = create_test_binary(dir.path(), "san_binary");

        let harness = Harness::new(&main_bin, None, false)?.with_sanitizer(Some(san_bin))?;

        assert!(harness.sanitizer_bin.is_some());
        assert!(harness.cmplog_bin.is_none());
        Ok(())
    }

    #[test]
    fn test_builder_methods() -> Result<(), HarnessError> {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");
        let san_bin = create_test_binary(dir.path(), "san_binary");
        let cmp_bin = create_test_binary(dir.path(), "cmp_binary");

        let harness = Harness::new(&main_bin, None, false)?
            .with_sanitizer(Some(&san_bin))?
            .with_cmplog(Some(&cmp_bin))?
            .with_coverage(Some(cmp_bin.clone()))?;

        assert!(harness.sanitizer_bin.is_some());
        assert!(harness.cmplog_bin.is_some());
        assert!(harness.cov_bin.is_some());

        Ok(())
    }

    #[test]
    fn test_builder_with_none() -> Result<(), HarnessError> {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");

        let harness = Harness::new(&main_bin, None, false)?
            .with_sanitizer(None::<PathBuf>)?
            .with_cmplog(None::<PathBuf>)?;

        assert!(harness.sanitizer_bin.is_none());
        assert!(harness.cmplog_bin.is_none());

        Ok(())
    }

    #[test]
    fn test_builder_with_invalid_path() {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");
        let invalid_bin = dir.path().join("nonexistent");

        let result =
            Harness::new(&main_bin, None, false).and_then(|h| h.with_sanitizer(Some(invalid_bin)));

        assert!(matches!(result, Err(HarnessError::InvalidBinary(_))));
    }
    #[test]
    fn test_resolve_binary() {
        let dir = tempdir().unwrap();
        let bin_path = create_test_binary(dir.path(), "test_binary");

        // Test with PathBuf
        let result = Harness::resolve_binary(bin_path.clone(), false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), fs::canonicalize(&bin_path).unwrap());

        // Test with &Path
        let result = Harness::resolve_binary(&bin_path, false);
        assert!(result.is_ok());

        // Test with &str
        let result = Harness::resolve_binary(bin_path.to_str().unwrap(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_binary_invalid() {
        let result = Harness::resolve_binary(PathBuf::from("/nonexistent/binary"), false);
        assert!(matches!(result, Err(HarnessError::InvalidBinary(_))));
    }
}
