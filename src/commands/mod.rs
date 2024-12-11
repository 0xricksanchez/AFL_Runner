pub mod cov;
pub mod gen;
pub mod kill;
pub mod render_tui;
pub mod run;

use anyhow::Result;

pub trait Command {
    /// Execute the command
    ///
    /// # Errors
    /// * If the command could not be executed
    fn execute(&self) -> Result<()>;
}
