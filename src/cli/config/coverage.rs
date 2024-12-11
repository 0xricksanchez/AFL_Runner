use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct CoverageConfig {
    /// HTML- or Text-based coverage report
    pub report_type: Option<String>,
    /// Split coverage report
    pub split_report: Option<bool>,
    /// Misc llvm-cov show arguments
    pub misc_show_args: Option<Vec<String>>,
    /// Misc llvm-cov report arguments
    pub misc_report_args: Option<Vec<String>>,
}
