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
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinary(path) => write!(f, "Invalid binary path: {}", path.display()),
            Self::PathResolution(path, err) => {
                write!(f, "Failed to resolve path {}: {}", path.display(), err)
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
}

impl Harness {
    /// Creates a new `Harness` instance
    ///
    /// # Arguments
    ///
    /// * `target_binary` - Path to the target binary
    /// * `target_args` - Optional vector of arguments for the harness
    ///
    /// # Errors
    ///
    /// Returns `HarnessError` if the target binary is invalid or cannot be resolved
    pub fn new<P: AsRef<Path>>(
        target_binary: P,
        target_args: Option<Vec<String>>,
    ) -> Result<Self, HarnessError> {
        let target_bin = Self::resolve_binary(target_binary.as_ref())?;
        let target_args = target_args.map(|args| args.join(" "));

        Ok(Self {
            target_bin,
            sanitizer_bin: None,
            cmplog_bin: None,
            cmpcov_bin: None,
            cov_bin: None,
            target_args,
        })
    }

    // Added getters for all fields
    #[inline]
    pub fn target_bin(&self) -> &Path {
        &self.target_bin
    }

    #[inline]
    pub fn sanitizer_bin(&self) -> Option<&Path> {
        self.sanitizer_bin.as_deref()
    }

    #[inline]
    pub fn cmplog_bin(&self) -> Option<&Path> {
        self.cmplog_bin.as_deref()
    }

    #[inline]
    pub fn cmpcov_bin(&self) -> Option<&Path> {
        self.cmpcov_bin.as_deref()
    }

    #[inline]
    pub fn cov_bin(&self) -> Option<&Path> {
        self.cov_bin.as_deref()
    }

    #[inline]
    pub fn target_args(&self) -> Option<&str> {
        self.target_args.as_deref()
    }

    /// Helper method to process optional binary paths
    fn process_optional_binary<P>(binary: Option<P>) -> Result<Option<PathBuf>, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        binary.map(Self::resolve_binary).transpose()
    }

    /// Sets the sanitizer binary
    pub fn with_sanitizer<P>(mut self, sanitizer_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.sanitizer_bin = Self::process_optional_binary(sanitizer_bin)?;
        Ok(self)
    }

    /// Sets the cmplog binary
    pub fn with_cmplog<P>(mut self, cmplog_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.cmplog_bin = Self::process_optional_binary(cmplog_bin)?;
        Ok(self)
    }

    /// Sets the cmpcov binary
    pub fn with_cmpcov<P>(mut self, cmpcov_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.cmpcov_bin = Self::process_optional_binary(cmpcov_bin)?;
        Ok(self)
    }

    /// Sets the code-coverage binary
    pub fn with_coverage<P>(mut self, cov_bin: Option<P>) -> Result<Self, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        self.cov_bin = Self::process_optional_binary(cov_bin)?;
        Ok(self)
    }

    /// Resolves a binary path to its canonical form
    ///
    /// # Arguments
    ///
    /// * `binary` - Path to the binary to resolve
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf, HarnessError>` - Canonical path if successful
    fn resolve_binary<P>(binary: P) -> Result<PathBuf, HarnessError>
    where
        P: Into<PathBuf> + AsRef<Path>,
    {
        // Convert once to PathBuf to avoid multiple conversions
        let binary_path = binary.into();

        if !binary_path.is_file() {
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

        let harness = Harness::new(&bin_path, Some(target_args)).unwrap();
        assert_eq!(harness.target_bin(), fs::canonicalize(&bin_path).unwrap());
        assert_eq!(harness.target_args(), Some("--arg1 --arg2"));
    }

    #[test]
    fn test_invalid_binary() {
        let non_existent = PathBuf::from("/nonexistent/binary");
        assert!(matches!(
            Harness::new(&non_existent, None),
            Err(HarnessError::InvalidBinary(_))
        ));
    }

    #[test]
    fn test_getters() -> Result<(), HarnessError> {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");
        let san_bin = create_test_binary(dir.path(), "san_binary");

        let harness = Harness::new(&main_bin, None)?.with_sanitizer(Some(san_bin))?;

        assert!(harness.sanitizer_bin().is_some());
        assert!(harness.cmplog_bin().is_none());
        Ok(())
    }

    #[test]
    fn test_builder_methods() -> Result<(), HarnessError> {
        let dir = tempdir().unwrap();
        let main_bin = create_test_binary(dir.path(), "main_binary");
        let san_bin = create_test_binary(dir.path(), "san_binary");
        let cmp_bin = create_test_binary(dir.path(), "cmp_binary");

        let harness = Harness::new(&main_bin, None)?
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

        let harness = Harness::new(&main_bin, None)?
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
            Harness::new(&main_bin, None).and_then(|h| h.with_sanitizer(Some(invalid_bin)));

        assert!(matches!(result, Err(HarnessError::InvalidBinary(_))));
    }
    #[test]
    fn test_resolve_binary() {
        let dir = tempdir().unwrap();
        let bin_path = create_test_binary(dir.path(), "test_binary");

        // Test with PathBuf
        let result = Harness::resolve_binary(bin_path.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), fs::canonicalize(&bin_path).unwrap());

        // Test with &Path
        let result = Harness::resolve_binary(&bin_path);
        assert!(result.is_ok());

        // Test with &str
        let result = Harness::resolve_binary(bin_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_binary_invalid() {
        let result = Harness::resolve_binary(PathBuf::from("/nonexistent/binary"));
        assert!(matches!(result, Err(HarnessError::InvalidBinary(_))));
    }
}
