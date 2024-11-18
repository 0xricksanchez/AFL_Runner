use crate::afl_cmd::AflCmd;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::{fmt, path::PathBuf};

/// These structs contain the AFL strategies and their probabilities of being applied in the command generation.
/// The values and probabilities are loosely based on the following AFL documentation:
/// `https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores`
/// Static empty set for default case
pub static EMPTY_INDICES: Lazy<HashSet<usize>> = Lazy::new(HashSet::new);

/// Configuration for CMPCOV instrumentation
#[derive(Debug, Clone)]
pub struct CmpcovConfig {
    /// Path to CMPCOV binary
    pub binary: PathBuf,
    /// Indices where CMPCOV was applied
    pub applied_indices: HashSet<usize>,
}

impl Default for CmpcovConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::new(),
            applied_indices: HashSet::new(),
        }
    }
}

impl CmpcovConfig {
    /// Creates a new CMPCOV configuration
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            applied_indices: HashSet::new(),
        }
    }

    /// Calculate maximum CMPCOV instances based on number of runners
    pub fn calculate_max_instances(runner_count: usize) -> usize {
        match runner_count {
            0..=2 => 0,
            3..=7 => 1,
            8..=15 => 2,
            _ => 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CmplogMode {
    Standard,   // -l 2
    Extended,   // -l 3
    Transforms, // -l 2AT
}

impl fmt::Display for CmplogMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "-l 2"),
            Self::Extended => write!(f, "-l 3"),
            Self::Transforms => write!(f, "-l 2AT"),
        }
    }
}

/// Configuration for CMPLOG instrumentation
#[derive(Debug, Clone)]
pub struct CmplogConfig {
    /// Path to CMPLOG binary
    pub binary: PathBuf,
    /// Percentage of runners to use CMPLOG (0.0 - 1.0)
    pub runner_ratio: f64,
    /// Distribution of CMPLOG modes
    pub mode_distribution: Vec<(CmplogMode, f64)>,
}

impl Default for CmplogConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::new(),
            runner_ratio: 0.3,
            mode_distribution: vec![
                (CmplogMode::Standard, 0.7),
                (CmplogMode::Extended, 0.1),
                (CmplogMode::Transforms, 0.2),
            ],
        }
    }
}

impl CmplogConfig {
    /// Creates a new CMPLOG configuration
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            runner_ratio: 0.3,
            mode_distribution: vec![
                (CmplogMode::Standard, 0.7),
                (CmplogMode::Extended, 0.1),
                (CmplogMode::Transforms, 0.2),
            ],
        }
    }
}

/// Represents different types of AFL mutation modes
#[derive(Debug, Clone, Copy)]
pub enum MutationMode {
    Explore,
    Exploit,
}

impl fmt::Display for MutationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explore => write!(f, "-P explore"),
            Self::Exploit => write!(f, "-P exploit"),
        }
    }
}

/// Represents different input format types
#[derive(Debug, Clone, Copy)]
pub enum FormatMode {
    Binary,
    Text,
}

impl fmt::Display for FormatMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary => write!(f, "-a binary"),
            Self::Text => write!(f, "-a text"),
        }
    }
}

/// Represents power schedule options
#[derive(Debug, Clone, Copy)]
pub enum PowerSchedule {
    Fast,
    Explore,
    Coe,
    Lin,
    Quad,
    Exploit,
    Rare,
}

impl fmt::Display for PowerSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let schedule = match self {
            Self::Fast => "fast",
            Self::Explore => "explore",
            Self::Coe => "coe",
            Self::Lin => "lin",
            Self::Quad => "quad",
            Self::Exploit => "exploit",
            Self::Rare => "rare",
        };
        write!(f, "-p {schedule}")
    }
}

/// Represents how multiple flags of the same type should be applied
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationMode {
    /// Only one flag of this type can be applied to each command
    Exclusive,
    /// Multiple flags of this type can be applied to each command
    Multiple,
}

/// Configuration for optional AFL features
#[derive(Debug, Clone)]
pub struct MiscFeatures {
    /// Probability of enabling deterministic fuzzing (`AFL_DISABLE_DETERMINISTIC`)
    /// -L 0 flag
    pub deterministic_fuzzing: Option<f64>,
    /// Probability of enabling sequential queue cycling (-Z)
    pub queue_cycling: Option<f64>,
    /// Application mode for optional features
    pub application_mode: ApplicationMode,
}

impl Default for MiscFeatures {
    fn default() -> Self {
        Self {
            deterministic_fuzzing: Some(0.1), // -L 0
            queue_cycling: Some(0.1),         // -Z
            application_mode: ApplicationMode::Multiple,
        }
    }
}

/// Comprehensive AFL strategy configuration
#[derive(Debug, Clone)]
pub struct AflStrategy {
    /// Available mutation modes with their probabilities
    pub mutation_modes: Vec<(MutationMode, f64)>,
    /// Available format modes with their probabilities
    pub format_modes: Vec<(FormatMode, f64)>,
    /// List of power schedules to cycle through
    pub power_schedules: Vec<PowerSchedule>,
    /// Optional features configuration
    pub optional_features: MiscFeatures,
    /// CMPLOG configuration
    pub cmplog_config: Option<CmplogConfig>,
    /// CMPCOV configuration
    pub cmpcov_config: Option<CmpcovConfig>,
}

impl Default for AflStrategy {
    fn default() -> Self {
        Self {
            mutation_modes: vec![(MutationMode::Explore, 0.4), (MutationMode::Exploit, 0.2)],
            format_modes: vec![(FormatMode::Binary, 0.3), (FormatMode::Text, 0.3)],
            power_schedules: vec![
                PowerSchedule::Fast,
                PowerSchedule::Explore,
                PowerSchedule::Coe,
                PowerSchedule::Lin,
                PowerSchedule::Quad,
                PowerSchedule::Exploit,
                PowerSchedule::Rare,
            ],
            optional_features: MiscFeatures::default(),
            cmplog_config: None,
            cmpcov_config: None,
        }
    }
}

impl AflStrategy {
    /// Creates a new strategy builder
    pub fn new() -> AflStrategyBuilder {
        AflStrategyBuilder::default()
    }

    /// Applies the strategy to a slice of AFL commands
    pub fn apply<R: rand::Rng>(
        &self,
        cmds: &mut [AflCmd],
        rng: &mut R,
        is_using_custom_mutator: bool,
    ) {
        // Apply mutation modes (exclusively)
        if !self.mutation_modes.is_empty() {
            Self::apply_exclusive_args(
                cmds,
                &self
                    .mutation_modes
                    .iter()
                    .map(|(mode, prob)| (mode.to_string(), *prob))
                    .collect::<Vec<_>>(),
                rng,
            );
        }

        // Apply format modes (exclusively)
        if !self.format_modes.is_empty() {
            Self::apply_exclusive_args(
                cmds,
                &self
                    .format_modes
                    .iter()
                    .map(|(mode, prob)| (mode.to_string(), *prob))
                    .collect::<Vec<_>>(),
                rng,
            );
        }

        // Apply power schedules
        if !self.power_schedules.is_empty() {
            self.apply_power_schedules(cmds);
        }

        // Apply optional features
        self.apply_optional_features(cmds, rng, is_using_custom_mutator);
    }

    /// Applies mutually exclusive arguments to commands
    fn apply_exclusive_args<R: rand::Rng>(
        cmds: &mut [AflCmd],
        args: &[(String, f64)],
        rng: &mut R,
    ) {
        let n = cmds.len();

        // Find commands that don't have any of these args yet
        let mut available_indices: Vec<usize> = (0..n)
            .filter(|&i| {
                !cmds[i]
                    .misc_afl_flags
                    .iter()
                    .any(|f| args.iter().any(|(arg, _)| f.contains(arg)))
            })
            .collect();

        available_indices.shuffle(rng);

        // Apply args according to their percentages
        let mut current_idx = 0;
        for (arg, percentage) in args {
            let count = (n as f64 * percentage) as usize;
            let end_idx = (current_idx + count).min(available_indices.len());

            for &index in &available_indices[current_idx..end_idx] {
                cmds[index].misc_afl_flags.push(arg.clone());
            }

            current_idx = end_idx;
        }
    }

    /// Applies optional features based on configuration and application mode
    fn apply_optional_features<R: rand::Rng>(
        &self,
        cmds: &mut [AflCmd],
        rng: &mut R,
        is_using_custom_mutator: bool,
    ) {
        let features = &self.optional_features;
        let mode = features.application_mode;

        let mut optional_args = Vec::new();

        // Collect all applicable optional features
        if !is_using_custom_mutator {
            if let Some(prob) = features.deterministic_fuzzing {
                optional_args.push(("-L 0".to_string(), prob));
            }
        }

        if let Some(prob) = features.queue_cycling {
            optional_args.push(("-Z".to_string(), prob));
        }

        // Apply according to mode
        match mode {
            ApplicationMode::Exclusive => Self::apply_exclusive_args(cmds, &optional_args, rng),
            ApplicationMode::Multiple => {
                for cmd in cmds {
                    for (arg, prob) in &optional_args {
                        if rng.gen::<f64>() < *prob {
                            cmd.misc_afl_flags.push(arg.clone());
                        }
                    }
                }
            }
        }
    }

    /// Applies power schedules to commands
    fn apply_power_schedules(&self, cmds: &mut [AflCmd]) {
        for (i, cmd) in cmds.iter_mut().enumerate() {
            if let Some(schedule) = self.power_schedules.get(i % self.power_schedules.len()) {
                cmd.misc_afl_flags.push(schedule.to_string());
            }
        }
    }

    /// Applies CMPLOG instrumentation to the specified number of AFL commands
    pub fn apply_cmplog<R: rand::Rng>(&self, cmds: &mut [AflCmd], rng: &mut R) {
        if self.cmplog_config.is_none() {
            return;
        }
        let config = self.cmplog_config.as_ref().unwrap();
        let num_cmplog_cfgs = (cmds.len() as f64 * config.runner_ratio) as usize;

        match num_cmplog_cfgs {
            0 => {}
            1 => Self::apply_single_cmplog(cmds, config),
            2 => Self::apply_double_cmplog(cmds, config),
            3 => Self::apply_triple_cmplog(cmds, config),
            _ => Self::apply_many_cmplog(cmds, num_cmplog_cfgs, config, rng),
        }
    }

    fn apply_single_cmplog(cmds: &mut [AflCmd], config: &CmplogConfig) {
        if let Some(cmd) = cmds.get_mut(1) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Transforms,
                config.binary.display()
            ));
        }
    }

    fn apply_double_cmplog(cmds: &mut [AflCmd], config: &CmplogConfig) {
        if let Some(cmd) = cmds.get_mut(1) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Standard,
                config.binary.display()
            ));
        }
        if let Some(cmd) = cmds.get_mut(2) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Transforms,
                config.binary.display()
            ));
        }
    }

    fn apply_triple_cmplog(cmds: &mut [AflCmd], config: &CmplogConfig) {
        if let Some(cmd) = cmds.get_mut(1) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Standard,
                config.binary.display()
            ));
        }
        if let Some(cmd) = cmds.get_mut(2) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Transforms,
                config.binary.display()
            ));
        }
        if let Some(cmd) = cmds.get_mut(3) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Extended,
                config.binary.display()
            ));
        }
    }

    fn apply_many_cmplog<R: rand::Rng>(
        cmds: &mut [AflCmd],
        num_cmplog_cfgs: usize,
        config: &CmplogConfig,
        rng: &mut R,
    ) {
        if num_cmplog_cfgs >= cmds.len() {
            return;
        }

        // Convert CmplogMode to string arguments with probabilities
        let mode_args: Vec<(String, f64)> = config
            .mode_distribution
            .iter()
            .map(|(mode, prob)| (mode.to_string(), *prob))
            .collect();

        // Apply modes exclusively to the selected range
        Self::apply_exclusive_args(&mut cmds[1..=num_cmplog_cfgs], &mode_args, rng);

        // Add the binary path to all CMPLOG-enabled commands
        for cmd in &mut cmds[1..=num_cmplog_cfgs] {
            cmd.misc_afl_flags
                .push(format!("-c {}", config.binary.display()));
        }
    }

    /// Applies CMPCOV instrumentation to commands
    pub fn apply_cmpcov<R: rand::Rng>(&mut self, cmds: &mut [AflCmd], rng: &mut R) {
        if self.cmpcov_config.is_none() {
            return;
        }
        let config = self.cmpcov_config.as_mut().unwrap();

        let max_instances = CmpcovConfig::calculate_max_instances(cmds.len());
        if max_instances == 0 {
            return;
        }

        // Find available indices (not using CMPLOG)
        let mut available_indices: Vec<usize> = (1..cmds.len())
            .filter(|i| !cmds[*i].misc_afl_flags.iter().any(|f| f.contains("-c")))
            .collect();

        if available_indices.is_empty() {
            return;
        }

        available_indices.shuffle(rng);

        // Apply CMPCOV to selected indices
        for &idx in available_indices.iter().take(max_instances) {
            cmds[idx].target_binary.clone_from(&config.binary);
            config.applied_indices.insert(idx);
        }
    }

    /// Get indices where CMPCOV was applied
    pub fn get_cmpcov_indices(&self) -> &HashSet<usize> {
        self.cmpcov_config
            .as_ref()
            .map_or(&EMPTY_INDICES, |c| &c.applied_indices)
    }
}

/// Builder for `AflStrategy`
#[derive(Default)]
pub struct AflStrategyBuilder {
    mutation_modes: Vec<(MutationMode, f64)>,
    format_modes: Vec<(FormatMode, f64)>,
    power_schedules: Vec<PowerSchedule>,
    optional_features: MiscFeatures,
    cmplog_config: Option<CmplogConfig>,
    cmpcov_config: Option<CmpcovConfig>,
}

impl AflStrategyBuilder {
    pub fn with_mutation_modes(mut self) -> Self {
        self.mutation_modes = vec![(MutationMode::Explore, 0.4), (MutationMode::Exploit, 0.2)];
        self
    }

    pub fn with_test_case_format(mut self) -> Self {
        self.format_modes = vec![(FormatMode::Binary, 0.3), (FormatMode::Text, 0.3)];
        self
    }

    pub fn with_power_schedules(mut self) -> Self {
        self.power_schedules = vec![
            PowerSchedule::Fast,
            PowerSchedule::Explore,
            PowerSchedule::Coe,
            PowerSchedule::Lin,
            PowerSchedule::Quad,
            PowerSchedule::Exploit,
            PowerSchedule::Rare,
        ];
        self
    }

    pub fn with_deterministic_fuzzing(mut self) -> Self {
        self.optional_features.deterministic_fuzzing = Some(0.1);
        self
    }

    pub fn with_seq_queue_cycling(mut self) -> Self {
        self.optional_features.queue_cycling = Some(0.1);
        self
    }

    pub fn with_cmplog(mut self, config: CmplogConfig) -> Self {
        self.cmplog_config = Some(config);
        self
    }

    pub fn with_cmpcov(mut self, config: CmpcovConfig) -> Self {
        self.cmpcov_config = Some(config);
        self
    }

    pub fn build(self) -> AflStrategy {
        AflStrategy {
            mutation_modes: self.mutation_modes,
            format_modes: self.format_modes,
            power_schedules: self.power_schedules,
            optional_features: self.optional_features,
            cmplog_config: self.cmplog_config,
            cmpcov_config: self.cmpcov_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use std::path::Path;

    // Helper function to create a deterministic RNG for testing
    fn get_test_rng() -> impl rand::Rng {
        rand::rngs::StdRng::seed_from_u64(42)
    }

    // Helper function to create test AFL commands
    fn create_test_cmds(count: usize) -> Vec<AflCmd> {
        let binary = PathBuf::from("/bin/afl-fuzz");
        let target = PathBuf::from("/bin/target");
        vec![AflCmd::new(binary, target); count]
    }

    mod builder_tests {
        use super::*;

        #[test]
        fn test_builder_default() {
            let strategy = AflStrategy::new().build();
            assert!(strategy.mutation_modes.is_empty());
            assert!(strategy.format_modes.is_empty());
            assert!(strategy.power_schedules.is_empty());
            assert!(strategy.cmplog_config.is_none());
            assert!(strategy.cmpcov_config.is_none());
        }

        #[test]
        fn test_builder_with_all_options() {
            let strategy = AflStrategy::new()
                .with_mutation_modes()
                .with_test_case_format()
                .with_power_schedules()
                .with_seq_queue_cycling()
                .with_cmplog(CmplogConfig::new(PathBuf::from("/bin/cmplog")))
                .with_cmpcov(CmpcovConfig::new(PathBuf::from("/bin/cmpcov")))
                .build();

            assert_eq!(strategy.mutation_modes.len(), 2);
            assert_eq!(strategy.format_modes.len(), 2);
            assert_eq!(strategy.power_schedules.len(), 7);
            assert!(strategy.cmplog_config.is_some());
            assert!(strategy.cmpcov_config.is_some());
        }
    }

    mod application_tests {
        use super::*;

        #[test]
        fn test_apply_mutation_modes() {
            let mut rng = get_test_rng();
            let strategy = AflStrategy::new().with_mutation_modes().build();

            let mut cmds = create_test_cmds(10);
            strategy.apply(&mut cmds, &mut rng, false);

            let explore_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f == "-P explore"))
                .count();
            let exploit_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f == "-P exploit"))
                .count();

            println!("{:?}", cmds);
            assert_eq!(explore_count, 4); // 40% of 10
            assert_eq!(exploit_count, 2); // 20% of 10
        }

        #[test]
        fn test_apply_format_modes() {
            let mut rng = get_test_rng();
            let strategy = AflStrategy::new().with_test_case_format().build();

            let mut cmds = create_test_cmds(10);
            strategy.apply(&mut cmds, &mut rng, false);

            let binary_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f == "-a binary"))
                .count();
            let text_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f == "-a text"))
                .count();

            assert_eq!(binary_count, 3); // 30% of 10
            assert_eq!(text_count, 3); // 30% of 10
        }

        #[test]
        fn test_apply_power_schedules() {
            let strategy = AflStrategy::new().with_power_schedules().build();

            let mut cmds = create_test_cmds(10);
            strategy.apply(&mut cmds, &mut get_test_rng(), false);

            // Verify power schedules are applied cyclically
            for (i, cmd) in cmds.iter().enumerate() {
                let schedule = &strategy.power_schedules[i % strategy.power_schedules.len()];
                assert!(cmd.misc_afl_flags.contains(&schedule.to_string()));
            }
        }

        #[test]
        fn test_optional_features() {
            let mut rng = get_test_rng();
            let mut strategy = AflStrategy::new().build();
            strategy.optional_features.deterministic_fuzzing = Some(1.0);
            strategy.optional_features.queue_cycling = Some(1.0);
            strategy.optional_features.application_mode = ApplicationMode::Multiple;

            // Test without custom mutator
            let mut cmds = create_test_cmds(5);
            strategy.apply(&mut cmds, &mut rng, false);

            // In Multiple mode, both flags should be present
            for cmd in &cmds {
                assert!(cmd.misc_afl_flags.contains(&"-L 0".to_string()));
                assert!(cmd.misc_afl_flags.contains(&"-Z".to_string()));
                // Ensure no duplicates
                assert_eq!(
                    cmd.misc_afl_flags.iter().filter(|&f| f == "-L 0").count(),
                    1
                );
                assert_eq!(cmd.misc_afl_flags.iter().filter(|&f| f == "-Z").count(), 1);
            }

            // Test with custom mutator
            let mut cmds = create_test_cmds(5);
            strategy.apply(&mut cmds, &mut rng, true);

            for cmd in &cmds {
                assert!(!cmd.misc_afl_flags.contains(&"-L 0".to_string())); // Should not apply when using custom mutator
                assert!(cmd.misc_afl_flags.contains(&"-Z".to_string())); // Should still apply queue cycling
                assert_eq!(cmd.misc_afl_flags.iter().filter(|&f| f == "-Z").count(), 1);
            }
        }

        #[test]
        fn test_optional_features_exclusive_mode() {
            let mut rng = get_test_rng();
            let mut strategy = AflStrategy::new().build();
            // Set probabilities that sum to 1.0 to ensure exclusive application
            strategy.optional_features.deterministic_fuzzing = Some(0.5);
            strategy.optional_features.queue_cycling = Some(0.5);
            strategy.optional_features.application_mode = ApplicationMode::Exclusive;

            let mut cmds = create_test_cmds(10);
            strategy.apply(&mut cmds, &mut rng, false);

            // Count commands with each flag
            let l0_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.contains(&"-L 0".to_string()))
                .count();
            let z_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.contains(&"-Z".to_string()))
                .count();

            // Total should be 10 (all commands should have exactly one flag)
            assert_eq!(l0_count + z_count, 10);
            // Each flag should be applied to half the commands (with 0.5 probability each)
            assert_eq!(l0_count, 5);
            assert_eq!(z_count, 5);

            // Verify no command has both flags
            for cmd in &cmds {
                assert!(
                    (cmd.misc_afl_flags.contains(&"-L 0".to_string())
                        && !cmd.misc_afl_flags.contains(&"-Z".to_string()))
                        || (!cmd.misc_afl_flags.contains(&"-L 0".to_string())
                            && cmd.misc_afl_flags.contains(&"-Z".to_string()))
                );
            }
        }

        #[test]
        fn test_optional_features_exclusive_mode_full_probability() {
            let mut rng = get_test_rng();
            let mut strategy = AflStrategy::new().build();
            strategy.optional_features.deterministic_fuzzing = Some(1.0);
            strategy.optional_features.queue_cycling = Some(1.0);
            strategy.optional_features.application_mode = ApplicationMode::Exclusive;

            let mut cmds = create_test_cmds(10);
            strategy.apply(&mut cmds, &mut rng, false);

            // When both probabilities are 1.0, each command should still get exactly one flag
            let flag_count = cmds
                .iter()
                .map(|cmd| {
                    cmd.misc_afl_flags
                        .iter()
                        .filter(|&f| *f == "-L 0" || *f == "-Z")
                        .count()
                })
                .sum::<usize>();

            assert_eq!(flag_count, 10, "Each command should have exactly one flag");

            // Verify no command has both flags
            for cmd in &cmds {
                assert!(
                    (cmd.misc_afl_flags.contains(&"-L 0".to_string())
                        && !cmd.misc_afl_flags.contains(&"-Z".to_string()))
                        || (!cmd.misc_afl_flags.contains(&"-L 0".to_string())
                            && cmd.misc_afl_flags.contains(&"-Z".to_string())),
                    "Each command should have exactly one flag type"
                );
            }
        }
    }

    mod cmplog_tests {
        use super::*;

        #[test]
        fn test_single_cmplog() {
            let mut rng = get_test_rng();
            let strategy = AflStrategy::new()
                .with_cmplog(CmplogConfig {
                    binary: PathBuf::from("/bin/cmplog"),
                    runner_ratio: 0.2,
                    mode_distribution: vec![(CmplogMode::Transforms, 1.0)],
                })
                .build();

            let mut cmds = create_test_cmds(5);
            strategy.apply_cmplog(&mut cmds, &mut rng);

            assert!(cmds[1]
                .misc_afl_flags
                .contains(&format!("-l 2AT -c {}", Path::new("/bin/cmplog").display())));
        }

        #[test]
        fn test_multiple_cmplog() {
            let mut rng = get_test_rng();
            let strategy = AflStrategy::new()
                .with_cmplog(CmplogConfig {
                    binary: PathBuf::from("/bin/cmplog"),
                    runner_ratio: 0.6,
                    mode_distribution: vec![
                        (CmplogMode::Standard, 0.4),
                        (CmplogMode::Extended, 0.3),
                        (CmplogMode::Transforms, 0.3),
                    ],
                })
                .build();

            let mut cmds = create_test_cmds(10);
            strategy.apply_cmplog(&mut cmds, &mut rng);

            let cmplog_count = cmds
                .iter()
                .filter(|cmd| cmd.misc_afl_flags.iter().any(|f| f.contains("-c")))
                .count();
            assert_eq!(cmplog_count, 6); // 60% of 10
        }
    }

    mod cmpcov_tests {
        use super::*;

        #[test]
        fn test_cmpcov_max_instances() {
            let _config = CmpcovConfig::new(PathBuf::from("/bin/cmpcov"));

            assert_eq!(CmpcovConfig::calculate_max_instances(2), 0);
            assert_eq!(CmpcovConfig::calculate_max_instances(5), 1);
            assert_eq!(CmpcovConfig::calculate_max_instances(10), 2);
            assert_eq!(CmpcovConfig::calculate_max_instances(20), 3);
        }

        #[test]
        fn test_cmpcov_application() {
            let mut rng = get_test_rng();
            let mut strategy = AflStrategy::new()
                .with_cmpcov(CmpcovConfig::new(PathBuf::from("/bin/cmpcov")))
                .build();

            let mut cmds = create_test_cmds(10);
            strategy.apply_cmpcov(&mut cmds, &mut rng);

            let cmpcov_indices = strategy.get_cmpcov_indices();
            assert_eq!(cmpcov_indices.len(), 2); // For 10 runners, should get 2 CMPCOV instances

            for &idx in cmpcov_indices {
                assert_eq!(cmds[idx].target_binary, PathBuf::from("/bin/cmpcov"));
            }
        }

        #[test]
        fn test_cmpcov_with_cmplog_conflict() {
            let mut rng = get_test_rng();
            let mut strategy = AflStrategy::new()
                .with_cmplog(CmplogConfig {
                    binary: PathBuf::from("/bin/cmplog"),
                    runner_ratio: 0.5,
                    mode_distribution: vec![(CmplogMode::Standard, 1.0)],
                })
                .with_cmpcov(CmpcovConfig::new(PathBuf::from("/bin/cmpcov")))
                .build();

            let mut cmds = create_test_cmds(10);

            // Apply CMPLOG first
            strategy.apply_cmplog(&mut cmds, &mut rng);

            // Then apply CMPCOV
            strategy.apply_cmpcov(&mut cmds, &mut rng);

            // Verify CMPCOV wasn't applied to CMPLOG instances
            for (i, cmd) in cmds.iter().enumerate() {
                if cmd.misc_afl_flags.iter().any(|f| f.contains("-c")) {
                    assert!(!strategy.get_cmpcov_indices().contains(&i));
                }
            }
        }
    }

    mod display_tests {
        use super::*;

        #[test]
        fn test_mutation_mode_display() {
            assert_eq!(MutationMode::Explore.to_string(), "-P explore");
            assert_eq!(MutationMode::Exploit.to_string(), "-P exploit");
        }

        #[test]
        fn test_format_mode_display() {
            assert_eq!(FormatMode::Binary.to_string(), "-a binary");
            assert_eq!(FormatMode::Text.to_string(), "-a text");
        }

        #[test]
        fn test_power_schedule_display() {
            assert_eq!(PowerSchedule::Fast.to_string(), "-p fast");
            assert_eq!(PowerSchedule::Explore.to_string(), "-p explore");
            assert_eq!(PowerSchedule::Coe.to_string(), "-p coe");
            assert_eq!(PowerSchedule::Lin.to_string(), "-p lin");
            assert_eq!(PowerSchedule::Quad.to_string(), "-p quad");
            assert_eq!(PowerSchedule::Exploit.to_string(), "-p exploit");
            assert_eq!(PowerSchedule::Rare.to_string(), "-p rare");
        }

        #[test]
        fn test_cmplog_mode_display() {
            assert_eq!(CmplogMode::Standard.to_string(), "-l 2");
            assert_eq!(CmplogMode::Extended.to_string(), "-l 3");
            assert_eq!(CmplogMode::Transforms.to_string(), "-l 2AT");
        }
    }
}
