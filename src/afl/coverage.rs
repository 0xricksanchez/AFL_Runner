use anyhow::{bail, Context, Result};
use glob::glob;
use rayon::prelude::*;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};
use tempfile::TempDir;
use uuid::Uuid;

use crate::utils::system::get_user_input;

#[derive(Debug)]
struct QueueDirectory {
    path: PathBuf,
    instance_name: OsString,
}

#[derive(Debug)]
enum ReportType {
    Html {
        base_dir: PathBuf,
        instance: Option<usize>,
    },
    Text,
}

#[derive(Clone, Debug)]
pub struct CoverageCollector {
    target: PathBuf,
    afl_out: PathBuf,
    config: CollectorConfig,
    merged_profdata: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct CollectorConfig {
    target_args: Vec<String>,
    split_reporting: bool,
    is_html: bool,
    show_args: Vec<String>,
    report_args: Vec<String>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            target_args: Vec::new(),
            split_reporting: false,
            is_html: true,
            show_args: Vec::new(),
            report_args: Vec::new(),
        }
    }
}

impl CoverageCollector {
    /// Creates a new coverage collector for the given target binary and AFL++ output directory
    ///
    /// # Arguments
    /// * `target` - Path to the instrumented binary
    /// * `afl_out` - Path to the AFL++ output directory containing queue folders
    ///
    /// # Returns
    /// * `Result<Self>` - A new `CoverageCollector` instance or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any of the system requirements are not met
    /// - The target binary is not compiled with LLVM coverage instrumentation
    /// - The readelf command fails to execute
    pub fn new<P: AsRef<Path>>(target: P, afl_out: P) -> Result<Self> {
        Self::is_target_cov_compiled(&target)?;
        let progs = vec!["llvm-profdata", "llvm-cov", "genhtml", "lcov"];
        Self::are_reqs_met(&progs)?;

        Ok(Self {
            target: target.as_ref().to_path_buf(),
            afl_out: afl_out.as_ref().to_path_buf(),
            config: CollectorConfig::default(),
            merged_profdata: None,
        })
    }

    fn is_target_cov_compiled<P: AsRef<Path>>(path: P) -> Result<bool> {
        let output = Command::new("readelf")
            .arg("-s")
            .arg(path.as_ref())
            .output()?;

        if !output.status.success() {
            bail!("readelf command failed to execute",);
        }

        // Convert output bytes to string, ignoring invalid UTF-8 sequences
        let output_str = String::from_utf8_lossy(&output.stdout);

        // Check if any line contains "covrec"
        if output_str.lines().any(|line| line.contains("covrec")) {
            Ok(true)
        } else {
            bail!("Target binary is not compiled with LLVM coverage instrumentation");
        }
    }

    fn are_reqs_met(progs: &[&str]) -> Result<()> {
        for prog in progs {
            let output = Command::new(prog)
                .arg("--version")
                .output()
                .with_context(|| {
                    format!(
                        "Failed to execute {prog}. Please ensure that the required tools are installed",
                    )
                })?;

            if !output.status.success() {
                bail!(
                    "{} failed to execute (return code: {}) - {:?}",
                    prog,
                    output.status,
                    output.stderr
                );
            }
        }
        Ok(())
    }

    /// Sets the arguments to be passed to the target binary during coverage collection
    ///
    /// # Arguments
    /// * `args` - Vector of arguments to pass to the target
    pub fn with_target_args(&mut self, args: Vec<String>) -> &mut Self {
        self.config.target_args = args;
        self
    }

    /// Configures whether to generate separate reports for each queue directory
    ///
    /// # Arguments
    /// * `enabled` - If true, generates separate reports for each fuzzer instance
    pub fn with_split_report(&mut self, enabled: bool) -> &mut Self {
        self.config.split_reporting = enabled;
        self
    }

    /// Sets whether to generate HTML coverage reports instead of text reports
    ///
    /// # Arguments
    /// * `enabled` - If true, generates HTML reports; if false, generates text reports
    pub fn with_html(&mut self, enabled: bool) -> &mut Self {
        self.config.is_html = enabled;
        self
    }

    /// Sets additional arguments for the `llvm-cov show` command
    ///
    /// # Arguments
    /// * `args` - Vector of additional arguments to pass to `llvm-cov show`
    pub fn with_misc_show_args(&mut self, args: Vec<String>) -> &mut Self {
        self.config.show_args = args;
        self
    }

    /// Sets additional arguments for the `llvm-cov report` command
    ///
    /// # Arguments
    /// * `args` - Vector of additional arguments to pass to `llvm-cov report`
    pub fn with_misc_report_args(&mut self, args: Vec<String>) -> &mut Self {
        self.config.report_args = args;
        self
    }

    /// Collects coverage information for the target binary
    ///
    /// This function processes all queue files, generates raw coverage data,
    /// and creates either a unified report or separate reports for each fuzzer instance
    /// based on the configuration.
    ///
    /// # Errors
    /// * If the AFL++ output directory cannot be read
    pub fn collect(&mut self) -> Result<()> {
        let queue_dirs = self.find_queue_directories()?;

        if self.config.split_reporting {
            self.process_split_reports(queue_dirs)
        } else {
            self.process_unified_report(queue_dirs)
        }
    }

    fn process_split_reports(&mut self, queue_dirs: Vec<QueueDirectory>) -> Result<()> {
        for (idx, dir) in queue_dirs.into_iter().enumerate() {
            let tmp_dir = self.process_queue_directory(&dir)?;
            let output_file = self.afl_out.join(format!("merged_{idx}.profdata"));

            Self::merge_raw_coverage(&tmp_dir, &output_file)?;
            self.merged_profdata = Some(output_file);

            let report_type = if self.config.is_html {
                ReportType::Html {
                    base_dir: self.afl_out.join("coverage_html"),
                    instance: Some(idx),
                }
            } else {
                ReportType::Text
            };

            self.generate_report(report_type)?;
            fs::remove_dir_all(&tmp_dir).with_context(|| {
                format!(
                    "Failed to remove temporary directory: {}",
                    tmp_dir.display()
                )
            })?;
        }
        Ok(())
    }

    fn is_base_dir_remove(bdir: &Path) -> Result<()> {
        if bdir.exists() {
            println!(
                "[!] Existing HTML reports found in {}. Overwrite? [Y/n]",
                bdir.display()
            );

            if get_user_input() != 'y' {
                anyhow::bail!("Aborting");
            }
            fs::remove_dir_all(bdir).with_context(|| {
                format!("Failed to remove existing directory: {}", bdir.display())
            })?;
        }
        Ok(())
    }

    fn process_unified_report(&mut self, queue_dirs: Vec<QueueDirectory>) -> Result<()> {
        let tmp_dir = Self::create_persistent_tmpdir()?;

        let queue_files: Vec<_> = queue_dirs
            .into_iter()
            .flat_map(|dir| Self::collect_queue_files(&dir.path))
            .collect();

        println!("[*] Processing {} queue files", queue_files.len());
        self.process_queue_files(&queue_files, &tmp_dir);

        let output_file = self.afl_out.join("merged.profdata");
        Self::merge_raw_coverage(&tmp_dir, &output_file)?;
        self.merged_profdata = Some(output_file);

        let report_type = if self.config.is_html {
            let base_dir = self.afl_out.join("coverage_html");
            Self::is_base_dir_remove(&base_dir)?;
            ReportType::Html {
                base_dir: self.afl_out.join("coverage_html"),
                instance: None,
            }
        } else {
            ReportType::Text
        };

        self.generate_report(report_type)?;
        fs::remove_dir_all(&tmp_dir).with_context(|| {
            format!(
                "Failed to remove temporary directory: {}",
                tmp_dir.display()
            )
        })?;
        Ok(())
    }

    fn generate_report(&self, report_type: ReportType) -> Result<()> {
        let merged_profdata = self.get_merged_profdata()?;

        match report_type {
            ReportType::Html { base_dir, instance } => {
                let output_dir = if let Some(idx) = instance {
                    base_dir.join(format!("instance_{idx}"))
                } else {
                    base_dir
                };
                fs::create_dir_all(&output_dir)?;
                self.run_llvm_cov_show(merged_profdata, &output_dir)
            }
            ReportType::Text => self.run_llvm_cov_report(merged_profdata),
        }
    }

    fn run_llvm_cov_show(&self, profdata: &Path, output_dir: &Path) -> Result<()> {
        self.run_llvm_command(
            "show",
            profdata,
            &[
                "-format=html",
                "-o",
                &output_dir.to_string_lossy(),
                "-show-line-counts-or-regions",
                "-show-expansions",
            ],
            &self.config.show_args,
        )?;

        println!(
            "[*] Generated HTML coverage report in: {}",
            output_dir.display()
        );
        Ok(())
    }

    fn run_llvm_cov_report(&self, profdata: &Path) -> Result<()> {
        let status = Command::new("llvm-cov")
            .arg("report")
            .arg(&self.target)
            .arg("-instr-profile")
            .arg(profdata)
            .args(&self.config.report_args)
            .status()
            .with_context(|| "Failed to run llvm-cov report")?;

        if !status.success() {
            anyhow::bail!("llvm-cov report failed");
        }
        Ok(())
    }

    fn run_llvm_command(
        &self,
        subcommand: &str,
        profdata: &Path,
        additional_args: &[&str],
        config_args: &[String],
    ) -> Result<()> {
        let status = Command::new("llvm-cov")
            .arg(subcommand)
            .arg(&self.target)
            .arg("-instr-profile")
            .arg(profdata)
            .args(additional_args)
            .args(config_args)
            .status()
            .with_context(|| format!("Failed to run llvm-cov {subcommand}"))?;

        if !status.success() {
            anyhow::bail!("llvm-cov {} failed", subcommand);
        }
        Ok(())
    }

    fn find_queue_directories(&self) -> Result<Vec<QueueDirectory>> {
        let dirs: Vec<_> = fs::read_dir(&self.afl_out)
            .with_context(|| {
                format!(
                    "Failed to read AFL++ output directory: {}",
                    self.afl_out.display()
                )
            })?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let queue_path = entry.path().join("queue");
                if queue_path.is_dir() {
                    Some(QueueDirectory {
                        path: queue_path,
                        instance_name: entry.file_name(),
                    })
                } else {
                    None
                }
            })
            .collect();

        if dirs.is_empty() {
            anyhow::bail!("No queue directories found in {}", self.afl_out.display());
        }
        Ok(dirs)
    }

    fn collect_queue_files(queue_path: &Path) -> Vec<PathBuf> {
        fs::read_dir(queue_path)
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect()
    }

    fn process_queue_directory(&self, dir: &QueueDirectory) -> Result<PathBuf> {
        let tmp_dir = Self::create_persistent_tmpdir()?;
        let queue_files = Self::collect_queue_files(&dir.path);

        println!(
            "[+] Processing queue directory for instance: {} with {} entries",
            dir.instance_name.to_string_lossy(),
            queue_files.len()
        );

        self.process_queue_files(&queue_files, &tmp_dir);

        Ok(tmp_dir)
    }

    #[allow(clippy::cast_precision_loss)]
    fn process_queue_files(&self, queue_files: &[PathBuf], tmp_dir: &Path) {
        let start_time = Instant::now();
        let total_files = queue_files.len();

        queue_files.par_iter().for_each(|file_path| {
            let file_name = file_path.file_name().unwrap().to_str().unwrap();
            let dst_path = tmp_dir.join(format!("cov_{file_name}_.profraw"));

            if let Err(e) = self.run_target_with_input(file_path, &dst_path) {
                eprintln!("[-] Failed to process {file_name}: {e}");
            }
        });

        let total_time = start_time.elapsed();
        println!(
            "  [+] Finished in {:.1}s ({:.1} files/sec)",
            total_time.as_secs_f64(),
            total_files as f64 / total_time.as_secs_f64()
        );
    }

    fn run_target_with_input(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        if self.is_file_based_harness() {
            self.run_file_based_target(input_path, output_path)
        } else {
            self.run_stdin_based_target(input_path, output_path)
        }
    }

    fn is_file_based_harness(&self) -> bool {
        self.config.target_args.iter().any(|arg| arg == "@@")
    }

    fn run_file_based_target(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        // Filter out @@ from arguments and replace with actual input file
        let args: Vec<_> = self
            .config
            .target_args
            .iter()
            .filter(|&arg| arg != "@@")
            .collect();

        Command::new(&self.target)
            .args(args)
            .arg(input_path)
            .env("LLVM_PROFILE_FILE", output_path)
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .with_context(|| {
                format!(
                    "Failed to execute file-based target with input: {}",
                    input_path.display()
                )
            })?;
        Ok(())
    }

    fn run_stdin_based_target(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        let input_content = fs::read(input_path)
            .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

        let mut child = Command::new(&self.target)
            .args(&self.config.target_args)
            .env("LLVM_PROFILE_FILE", output_path)
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .with_context(|| "Failed to spawn stdin-based target")?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(&input_content)
                .with_context(|| "Failed to write to target's stdin")?;
            // Stdin will be closed when dropped
        }

        let status = child
            .wait()
            .with_context(|| "Failed to wait for target completion")?;

        if !status.success() {
            // This is expected for some inputs during fuzzing, so we just return Ok
            println!(
                "Note: Target exited with non-zero status for input: {}",
                input_path.display()
            );
        }
        Ok(())
    }

    fn merge_raw_coverage(raw_cov_dir: &Path, output_file: &Path) -> Result<()> {
        let pattern = raw_cov_dir.join("cov_*.profraw");
        let profraw_files: Vec<_> = glob(pattern.to_str().unwrap())?
            .filter_map(Result::ok)
            .collect();

        if profraw_files.is_empty() {
            anyhow::bail!("No .profraw files found in {}", raw_cov_dir.display());
        }

        // Create temporary directory for batch processing
        let temp_dir = TempDir::new()?;

        // Process files in parallel batches
        let temp_merged_files: Result<Vec<_>> = profraw_files
            .par_chunks(1000)
            .enumerate()
            .map(|(i, chunk)| {
                let temp_output = temp_dir.path().join(format!("temp_merged_{i}.profdata"));
                
                let output = Command::new("llvm-profdata")
                    .arg("merge")
                    .arg("-sparse")
                    .args(chunk)
                    .arg("-o")
                    .arg(&temp_output)
                    .output()?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!(
                        "Failed to merge coverage files (batch {}):\nCommand: llvm-profdata merge -sparse [...] -o {}\nError: {}",
                        i,
                        temp_output.display(),
                        stderr
                    );
                }

                Ok(temp_output)
            })
            .collect();

        let temp_merged_files = temp_merged_files?;

        // Final merge of temporary files
        let output = Command::new("llvm-profdata")
            .arg("merge")
            .arg("-sparse")
            .args(&temp_merged_files)
            .arg("-o")
            .arg(output_file)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Failed to merge temporary coverage files:\nCommand: llvm-profdata merge -sparse [...] -o {}\nError: {}",
                output_file.display(),
                stderr
            );
        }

        Ok(())
    }

    fn create_persistent_tmpdir() -> Result<PathBuf> {
        let tmp_dir = PathBuf::from("/tmp").join(format!(".aflr_cov_{}", Uuid::new_v4()));
        fs::create_dir(&tmp_dir)?;
        Ok(tmp_dir)
    }

    fn get_merged_profdata(&self) -> Result<&Path> {
        self.merged_profdata
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No merged profdata file available"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;

    fn setup_test_dir() -> Result<(PathBuf, PathBuf)> {
        let test_dir = PathBuf::from("/tmp").join(format!("test_coverage_{}", Uuid::new_v4()));
        fs::create_dir(&test_dir)?;

        // Create a mock AFL++ output directory
        let afl_dir = test_dir.join("afl_out");
        fs::create_dir(&afl_dir)?;

        // Create multiple fuzzer instance directories
        for i in 1..=3 {
            let instance_dir = afl_dir.join(format!("fuzzer{i:02}"));
            fs::create_dir(&instance_dir)?;
            let queue_dir = instance_dir.join("queue");
            fs::create_dir(&queue_dir)?;

            // Create multiple test input files
            for j in 0..3 {
                let input_file = queue_dir.join(format!("id:{j:06}"));
                File::create(&input_file)?.write_all(format!("test input {j}").as_bytes())?;
            }
        }

        Ok((test_dir, afl_dir))
    }

    fn create_mock_binary() -> Result<PathBuf> {
        // Create a simple test binary that we can use for coverage
        let test_dir = PathBuf::from("/tmp").join(format!("test_binary_{}", Uuid::new_v4()));
        fs::create_dir(&test_dir)?;

        let source_path = test_dir.join("test.c");
        fs::write(
            &source_path,
            r#"
            #include <stdio.h>
            int main(int argc, char *argv[]) {
                if (argc > 1) {
                    printf("Hello %s\n", argv[1]);
                }
                return 0;
            }
        "#,
        )?;

        let binary_path = test_dir.join("test_binary");
        Command::new("clang")
            .args(["-fprofile-instr-generate", "-fcoverage-mapping"])
            .arg("-o")
            .arg(&binary_path)
            .arg(&source_path)
            .status()
            .expect("Failed to compile test binary");

        Ok(binary_path)
    }

    #[test]
    fn test_find_queue_directories() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let (test_dir, afl_dir) = setup_test_dir()?;
        let collector = CoverageCollector::new(binary_path, afl_dir)?;

        let queue_dirs = collector.find_queue_directories()?;
        assert_eq!(queue_dirs.len(), 3); // We now create 3 fuzzer instances
        assert!(queue_dirs.iter().all(|dir| dir.path.ends_with("queue")));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn test_is_file_based_harness() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let mut collector = CoverageCollector::new(binary_path, "/tmp".into())?;
        assert!(!collector.is_file_based_harness());

        collector.with_target_args(vec!["@@".to_string()]);
        assert!(collector.is_file_based_harness());
        Ok(())
    }

    #[test]
    fn test_collector_config() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let mut collector = CoverageCollector::new(binary_path, "/tmp".into())?;
        collector
            .with_html(false)
            .with_split_report(true)
            .with_target_args(vec!["arg1".to_string()])
            .with_misc_show_args(vec!["--show-branches".to_string()])
            .with_misc_report_args(vec!["--show-functions".to_string()]);

        assert!(!collector.config.is_html);
        assert!(collector.config.split_reporting);
        assert_eq!(collector.config.target_args, vec!["arg1"]);
        assert_eq!(collector.config.show_args, vec!["--show-branches"]);
        assert_eq!(collector.config.report_args, vec!["--show-functions"]);

        Ok(())
    }

    #[test]
    fn test_collect_queue_files() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let (test_dir, afl_dir) = setup_test_dir()?;
        let collector = CoverageCollector::new(binary_path, afl_dir)?;

        let queue_dirs = collector.find_queue_directories()?;
        let files = CoverageCollector::collect_queue_files(&queue_dirs[0].path);

        assert_eq!(files.len(), 3); // Each queue directory has 3 files
        assert!(files.iter().all(|f| f.to_str().unwrap().contains("id:")));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn test_process_queue_directory() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let (test_dir, afl_dir) = setup_test_dir()?;

        let mut collector = CoverageCollector::new(&binary_path, &afl_dir)?;
        collector.with_target_args(vec!["@@".to_string()]);

        let queue_dirs = collector.find_queue_directories()?;
        let tmp_dir = collector.process_queue_directory(&queue_dirs[0])?;

        // Check that profraw files were created
        let profraw_count = glob(tmp_dir.join("cov_*.profraw").to_str().unwrap())?.count();
        assert_eq!(profraw_count, 3); // One for each input file

        fs::remove_dir_all(test_dir)?;
        fs::remove_dir_all(tmp_dir)?;
        fs::remove_dir_all(binary_path.parent().unwrap())?;
        Ok(())
    }

    #[test]
    fn test_invalid_afl_directory() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let collector = CoverageCollector::new(binary_path, "/nonexistent".into())?;
        assert!(collector.find_queue_directories().is_err());
        Ok(())
    }

    #[test]
    fn test_empty_afl_directory() -> Result<()> {
        let binary_path = create_mock_binary()?;
        let test_dir = PathBuf::from("/tmp").join(format!("test_coverage_{}", Uuid::new_v4()));
        fs::create_dir(&test_dir)?;

        let collector = CoverageCollector::new(binary_path, test_dir.clone())?;
        assert!(collector.find_queue_directories().is_err());

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }
}
