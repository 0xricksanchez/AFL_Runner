use clap::CommandFactory;
use clap_complete::{generate_to, shells::*};
use std::env;
use std::io::Error;
use std::path::PathBuf;

use afl_runner::cli::Cli;

fn main() -> Result<(), Error> {
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_else(|| "completions".into()));
    std::fs::create_dir_all(&outdir)?;

    let mut cmd = Cli::command();

    // Bash completion script
    let bash_dynamic = r##"
_aflr_kill_completion() {
    local cur=${COMP_WORDS[COMP_CWORD]}
    if [[ ${COMP_WORDS[1]} == "kill" ]]; then
        COMPREPLY=($(compgen -W "$(tmux ls 2>/dev/null | cut -d ':' -f 1)" -- "$cur"))
    fi
}

complete -F _aflr_kill_completion aflr
"##;

    // Zsh completion script
    let zsh_dynamic = r##"
#compdef aflr

_aflr_kill() {
    local sessions
    sessions=(${(f)"$(tmux ls 2>/dev/null | cut -d ':' -f 1)"})
    _describe 'tmux sessions' sessions
}

_aflr() {
    local line

    _arguments -C \
        "1: :->cmds" \
        "*::arg:->args"

    case "$line[1]" in
        kill)
            _aflr_kill
            ;;
    esac
}

compdef _aflr aflr
"##;

    // Write the dynamic completion scripts
    std::fs::write(outdir.join("aflr_dynamic.bash"), bash_dynamic)?;
    std::fs::write(outdir.join("aflr_dynamic.zsh"), zsh_dynamic)?;

    // Generate static completions (keeping these for reference)
    generate_to(Bash, &mut cmd, "aflr", &outdir)?;
    generate_to(Zsh, &mut cmd, "aflr", &outdir)?;
    generate_to(Fish, &mut cmd, "aflr", &outdir)?;

    println!("Generated completion scripts in: {}", outdir.display());
    println!("\nFor Bash, add this line to your ~/.bashrc:");
    println!("source {}/aflr_dynamic.bash", outdir.display());
    println!("\nFor Zsh, add this line to your ~/.zshrc:");
    println!("source {}/aflr_dynamic.zsh", outdir.display());
    println!("# or for Zsh, you can also copy the file to your completions directory:");
    println!(
        "cp {}/aflr_dynamic.zsh ~/.zsh/completions/_aflr",
        outdir.display()
    );

    Ok(())
}

