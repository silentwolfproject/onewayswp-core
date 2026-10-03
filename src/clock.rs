use crate::errors::{OnewayError, Result};
use crate::utils::now_unix;

pub const MAX_FORWARD_JUMP: i64 = 7 * 86400;

pub fn check_clock(last_known: i64, current: i64) -> Result<()> {
    if last_known <= 0 {
        return Ok(());
    }

    if current < last_known {
        return Err(OnewayError::ClockRollback);
    }

    if current > last_known + MAX_FORWARD_JUMP {
        return Err(OnewayError::ClockRollback);
    }

    Ok(())
}

pub fn now() -> i64 {
    now_unix()
}