use crate::afl_cmd::AflCmd;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::{fmt, path::PathBuf};

/// These structs contain the AFL strategies and their probabilities of being applied in the command generation.
/// The values and probabilities are loosely based on the following AFL documentation:
/// https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores

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
    /// Calculate maximum CMPCOV instances based on number of runners
    pub fn calculate_max_instances(&self, runner_count: usize) -> usize {
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApplicationMode {
    /// Only one flag of this type can be applied to each command
    Exclusive,
    /// Multiple flags of this type can be applied to each command
    Multiple,
}

/// Configuration for optional AFL features
#[derive(Debug, Clone)]
pub struct MiscFeatures {
    /// Probability of enabling deterministic fuzzing (AFL_DISABLE_DETERMINISTIC)
    /// -L 0 flag
    pub deterministic_fuzzing: Option<f64>,
    /// Probability of enabling MOpt mutator (-L)
    pub mopt_mutator: Option<f64>,
    /// Probability of enabling queue cycling (-Z)
    pub queue_cycling: Option<f64>,
    /// Application mode for optional features
    pub application_mode: ApplicationMode,
}

impl Default for MiscFeatures {
    fn default() -> Self {
        Self {
            deterministic_fuzzing: Some(0.1), // -L 0
            mopt_mutator: None,
            queue_cycling: Some(0.1), // -Z
            application_mode: ApplicationMode::Exclusive,
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
            self.apply_exclusive_args(
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
            self.apply_exclusive_args(
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
        &self,
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

        if let Some(prob) = features.mopt_mutator {
            optional_args.push(("-L".to_string(), prob));
        }

        if let Some(prob) = features.queue_cycling {
            optional_args.push(("-Z".to_string(), prob));
        }

        // Apply according to mode
        match mode {
            ApplicationMode::Exclusive => self.apply_exclusive_args(cmds, &optional_args, rng),
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

    /// Applies probabilistic arguments to commands
    fn apply_probabilistic_args<T, R>(&self, cmds: &mut [AflCmd], options: &[(T, f64)], rng: &mut R)
    where
        T: fmt::Display,
        R: rand::Rng,
    {
        for cmd in cmds {
            for (option, prob) in options {
                if rng.gen::<f64>() < *prob {
                    cmd.misc_afl_flags.push(option.to_string());
                    break;
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
            1 => self.apply_single_cmplog(cmds, config),
            2 => self.apply_double_cmplog(cmds, config),
            3 => self.apply_triple_cmplog(cmds, config),
            _ => self.apply_many_cmplog(cmds, num_cmplog_cfgs, config, rng),
        }
    }

    fn apply_single_cmplog(&self, cmds: &mut [AflCmd], config: &CmplogConfig) {
        if let Some(cmd) = cmds.get_mut(1) {
            cmd.misc_afl_flags.push(format!(
                "{} -c {}",
                CmplogMode::Standard,
                config.binary.display()
            ));
        }
    }

    fn apply_double_cmplog(&self, cmds: &mut [AflCmd], config: &CmplogConfig) {
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

    fn apply_triple_cmplog(&self, cmds: &mut [AflCmd], config: &CmplogConfig) {
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
        &self,
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
        self.apply_exclusive_args(&mut cmds[1..=num_cmplog_cfgs], &mode_args, rng);

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

        let max_instances = config.calculate_max_instances(cmds.len());
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
            cmds[idx].target_binary = config.binary.clone();
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

/// Combined configuration for all AFL instrumentation
#[derive(Debug, Clone)]
pub struct AflInstrumentation {
    pub cmplog: Option<CmplogConfig>,
    pub cmpcov: Option<CmpcovConfig>,
}

/// Builder for AflStrategy
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
    pub fn mutation_mode(mut self, mode: MutationMode, probability: f64) -> Self {
        self.mutation_modes.push((mode, probability));
        self
    }

    pub fn format_mode(mut self, mode: FormatMode, probability: f64) -> Self {
        self.format_modes.push((mode, probability));
        self
    }

    pub fn power_schedule(mut self, schedule: PowerSchedule) -> Self {
        self.power_schedules.push(schedule);
        self
    }

    pub fn deterministic_fuzzing(mut self, probability: Option<f64>) -> Self {
        self.optional_features.deterministic_fuzzing = probability;
        self
    }

    pub fn mopt_mutator(mut self, probability: Option<f64>) -> Self {
        self.optional_features.mopt_mutator = probability;
        self
    }

    pub fn queue_cycling(mut self, probability: Option<f64>) -> Self {
        self.optional_features.queue_cycling = probability;
        self
    }

    pub fn cmplog_config(mut self, config: CmplogConfig) -> Self {
        self.cmplog_config = Some(config);
        self
    }

    pub fn cmplog_binary<P: Into<PathBuf>>(mut self, binary: P) -> Self {
        self.ensure_cmplog_config();
        self.cmplog_config.as_mut().unwrap().binary = binary.into();
        self
    }

    pub fn cmplog_runner_ratio(mut self, ratio: f64) -> Self {
        self.ensure_cmplog_config();
        self.cmplog_config.as_mut().unwrap().runner_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn cmplog_mode(mut self, mode: CmplogMode, probability: f64) -> Self {
        self.ensure_cmplog_config();
        let config = self.cmplog_config.as_mut().unwrap();
        config.mode_distribution.push((mode, probability));
        self
    }

    fn ensure_cmplog_config(&mut self) {
        if self.cmplog_config.is_none() {
            self.cmplog_config = Some(CmplogConfig::default());
        }
    }

    pub fn cmpcov_config(mut self, config: CmpcovConfig) -> Self {
        self.cmpcov_config = Some(config);
        self
    }

    pub fn cmpcov_binary<P: Into<PathBuf>>(mut self, binary: P) -> Self {
        self.ensure_cmpcov_config();
        self.cmpcov_config.as_mut().unwrap().binary = binary.into();
        self
    }

    fn ensure_cmpcov_config(&mut self) {
        if self.cmpcov_config.is_none() {
            self.cmpcov_config = Some(CmpcovConfig::default());
        }
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

//[cfg(test)]
//mod tests {
//    use super::*;
//    use rand::thread_rng;
//
//    #[test]
//    fn test_default_strategy() {
//        let strategy = AflStrategy::default();
//        assert_eq!(strategy.mutation_modes.len(), 2);
//        assert_eq!(strategy.format_modes.len(), 2);
//        assert_eq!(strategy.power_schedules.len(), 7);
//    }
//
//    #[test]
//    fn test_builder() {
//        let strategy = AflStrategy::builder()
//            .mutation_mode(MutationMode::Explore, 0.5)
//            .format_mode(FormatMode::Binary, 0.3)
//            .power_schedule(PowerSchedule::Fast)
//            .deterministic_fuzzing(Some(0.2))
//            .build();
//
//        assert_eq!(strategy.mutation_modes.len(), 1);
//        assert_eq!(strategy.format_modes.len(), 1);
//        assert_eq!(strategy.power_schedules.len(), 1);
//        assert_eq!(strategy.optional_features.deterministic_fuzzing, Some(0.2));
//    }
//
//    #[test]
//    fn test_strategy_application() {
//        let mut cmds = vec![AflCmd::default(); 3];
//        let strategy = AflStrategy::default();
//        let mut rng = thread_rng();
//
//        strategy.apply(&mut cmds, &mut rng, false);
//
//        // Verify that power schedules were applied
//        for cmd in &cmds {
//            assert!(!cmd.misc_afl_flags.is_empty());
//        }
//    }
//}
