use std::fs;
use std::path::PathBuf;

pub struct Harness {
    // Instrumented and maybe AFL_HARDEN=1
    pub target_binary: PathBuf,
    // AFL_USE_*SAN=1
    pub sanitizer_binary: Option<PathBuf>,
    // AFL_LLVM_CMPLOG=1
    pub cmplog_binary: Option<PathBuf>,
    // Additional arguments for the harness
    // If the harness reads from stdin, use @@ as placeholder
    pub target_args: Option<String>,
}

impl Harness {
    pub fn new<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr> + std::fmt::Display>(
        target_binary: P,
        sanitizer_binary: Option<P>,
        cmplog_binary: Option<P>,
        target_args: Option<String>,
    ) -> Self {
        let target_binary = Self::_get_target_binary(target_binary);
        assert!(target_binary.is_some(), "Could not find target binary");

        let sanitizer_binary = Self::_get_sanitizer_binary(sanitizer_binary);
        let cmplog_binary = Self::_get_cmplog_binary(cmplog_binary);

        Self {
            target_binary: target_binary.unwrap(),
            sanitizer_binary,
            cmplog_binary,
            target_args: target_args.map(std::convert::Into::into),
        }
    }

    fn _is_path_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(path: &P) -> bool {
        let path: PathBuf = path.into();
        path.exists() && path.is_file()
    }

    fn _get_target_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(
        target_binary: P,
    ) -> Option<PathBuf> {
        let target_binary = target_binary.into();
        if Self::_is_path_binary(&target_binary) {
            let resolved_tbin = fs::canonicalize(target_binary).expect("Failed to resolve path");
            return Some(resolved_tbin);
        }
        None
    }

    fn _get_sanitizer_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(
        sanitizer_binary: Option<P>,
    ) -> Option<PathBuf> {
        let sanitizer_binary = sanitizer_binary.map_or_else(PathBuf::new, std::convert::Into::into);
        if Self::_is_path_binary(&sanitizer_binary) {
            let res_sbin = fs::canonicalize(sanitizer_binary).expect("Failed to resolve path");
            return Some(res_sbin);
        }
        None
    }

    fn _get_cmplog_binary<P: Into<PathBuf> + std::convert::AsRef<std::ffi::OsStr>>(
        cmplog_binary: Option<P>,
    ) -> Option<PathBuf> {
        let cmplog_binary = cmplog_binary.map_or_else(PathBuf::new, std::convert::Into::into);
        if Self::_is_path_binary(&cmplog_binary) {
            let cmpl_bin = fs::canonicalize(cmplog_binary).expect("Failed to resolve path");
            return Some(cmpl_bin);
        }
        None
    }
}
