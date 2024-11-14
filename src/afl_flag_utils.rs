
pub fn apply_flags(configs: &mut [AFLEnv], flag: &AFLFlag, percentage: f64, rng: &mut impl Rng) {
    let count = (configs.len() as f64 * percentage).round() as usize;
    let mut indices: HashSet<_> = (0..configs.len())
        .collect::<Vec<_>>()
        .choose_multiple(rng, count)
        .cloned()
        .collect();

    for index in indices {
        configs[index].enable_flag(flag.clone());
    }
}

pub fn apply_constrained_args_excl(cmds: &mut [AflCmd], args: &[(&str, f64)], rng: &mut impl Rng) {
    let mut available_indices: Vec<_> = (0..cmds.len())
        .filter(|&i| !args.iter().any(|(arg, _)| cmds[i].has_flag(arg)))
        .collect();
    available_indices.shuffle(rng);

    let mut current_idx = 0;
    for &(arg, percentage) in args {
        let count = (cmds.len() as f64 * percentage).round() as usize;
        let end_idx = (current_idx + count).min(available_indices.len());

        for &index in &available_indices[current_idx..end_idx] {
            cmds[index].add_flag(arg.to_string());
        }
        current_idx = end_idx;
    }
}

pub fn apply_constrained_args(cmds: &mut [AflCmd], args: &[(&str, f64)], rng: &mut impl Rng) {
    for &(arg, percentage) in args {
        let count = (cmds.len() as f64 * percentage).round() as usize;
        let available_indices: Vec<_> = (0..cmds.len())
            .filter(|&i| !cmds[i].has_flag(arg))
            .collect();

        for &index in available_indices.choose_multiple(rng, count) {
            cmds[index].add_flag(arg.to_string());
        }
    }
}

pub fn apply_args(cmds: &mut [AflCmd], arg: &str, percentage: f64, rng: &mut impl Rng) {
    let count = (cmds.len() as f64 * percentage).round() as usize;
    if count == 0 && percentage > 0.0 && cmds.len() > 3 {
        let idx = rng.gen_range(0..cmds.len());
        cmds[idx].add_flag(arg.to_string());
        return;
    }

    for index in (0..cmds.len())
        .collect::<Vec<_>>()
        .choose_multiple(rng, count)
    {
        cmds[*index].add_flag(arg.to_string());
    }
}
