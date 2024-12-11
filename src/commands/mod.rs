pub mod cov;
pub mod gen;
pub mod kill;
pub mod render_tui;
pub mod run;

use anyhow::Result;

pub trait Command {
    fn execute(&self) -> Result<()>;
}
