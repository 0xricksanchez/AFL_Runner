use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct TargetArgs {
    /// Path to the target binary
    pub path: Option<String>,
    /// Path to the sanitizer binary
    pub san_path: Option<String>,
    /// Path to the CMPLOG binary
    pub cmpl_path: Option<String>,
    /// Path to the CMPCOV binary
    pub cmpc_path: Option<String>,
    /// Path to the Coverage binary
    pub cov_path: Option<String>,
    /// Arguments for the target binary
    pub args: Option<Vec<String>>,
}
