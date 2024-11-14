use std::path::PathBuf;

/// Represents an AFL command configuration
#[derive(Debug, Clone)]
pub struct AflCmd {
    /// Path to the AFL binary
    pub afl_binary: PathBuf,
    /// Environment variables for the AFL command
    pub env: Vec<String>,
    /// Input directory for AFL
    pub input_dir: PathBuf,
    /// Output directory for AFL
    pub output_dir: PathBuf,
    /// Miscellaneous AFL flags
    pub misc_afl_flags: Vec<String>,
    /// Path to the target binary
    pub target_binary: PathBuf,
    /// Arguments for the target binary
    pub target_args: Option<String>,
}

impl AflCmd {
    pub fn new(afl_binary: PathBuf, target_binary: PathBuf) -> Self {
        Self {
            afl_binary,
            env: Vec::new(),
            input_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            misc_afl_flags: Vec::new(),
            target_binary,
            target_args: None,
        }
    }

    /// Sets the environment variables for the AFL command
    pub fn with_env(&mut self, env: Vec<String>, is_prepend: bool) -> &mut Self {
        if is_prepend {
            env.iter().for_each(|e| self.env.insert(0, e.clone()));
        } else {
            self.env.extend(env);
        }
        self
    }

    /// Sets the input directory for AFL
    pub fn with_input_dir(&mut self, input_dir: PathBuf) -> &mut Self {
        self.input_dir = input_dir;
        self
    }

    /// Sets the output directory for AFL
    pub fn with_output_dir(&mut self, output_dir: PathBuf) -> &mut Self {
        self.output_dir = output_dir;
        self
    }

    /// Sets the miscellaneous AFL flags
    pub fn with_misc_flags(&mut self, misc_flags: Vec<String>) -> &mut Self {
        self.misc_afl_flags = misc_flags;
        self
    }

    /// Sets the arguments for the target binary
    pub fn with_target_args(&mut self, target_args: Option<String>) -> &mut Self {
        self.target_args = target_args;
        self
    }

    /// Adds a flag to the miscellaneous AFL flags
    pub fn add_flag(&mut self, flag: String) {
        self.misc_afl_flags.push(flag);
    }

    /// Checks if a flag is present in the miscellaneous AFL flags
    pub fn has_flag(&self, flag: &str) -> bool {
        self.misc_afl_flags.iter().any(|f| f.contains(flag))
    }

    /// Assembles the AFL command into a string
    pub fn assemble(&self) -> String {
        let mut cmd_parts = Vec::new();
        cmd_parts.extend(self.env.iter().cloned());
        cmd_parts.push(self.afl_binary.display().to_string());
        cmd_parts.push(format!("-i {}", self.input_dir.display()));
        cmd_parts.push(format!("-o {}", self.output_dir.display()));
        cmd_parts.extend(self.misc_afl_flags.iter().cloned());
        cmd_parts.push(format!("-- {}", self.target_binary.display()));

        if let Some(args) = &self.target_args {
            cmd_parts.push(args.clone());
        }

        cmd_parts.join(" ").trim().replace("  ", " ")
    }
}
