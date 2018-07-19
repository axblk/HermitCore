use std::str::FromStr;

use hermit::error::*;

#[derive(Debug, Clone)]
pub enum MigrationType {
    Cold,
    Live
}

impl FromStr for MigrationType {
    type Err = Error;

    fn from_str(s: &str) -> Result<MigrationType> {
        match s {
            "cold" | "COLD" => Ok(MigrationType::Cold),
            "live" | "LIVE" => Ok(MigrationType::Live),
            _ => Err(Error::UnsupportedMigrationType(s.into())),
        }
    }
}
