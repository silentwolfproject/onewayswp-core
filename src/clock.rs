use crate::errors::{OnewayError, Result};
use crate::utils::now_unix;

pub fn check_clock(last_known: i64) -> Result<()> {
    let now = now_unix();
    if last_known > 0 && now < last_known {
        return Err(OnewayError::ClockRollback);
    }
    Ok(())
}