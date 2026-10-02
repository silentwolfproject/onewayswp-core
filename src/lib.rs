pub mod clock;
pub mod crypto;
pub mod errors;
pub mod ffi;
pub mod hardware;
pub mod keypair;
pub mod license;
pub mod response;
pub mod state;
pub mod utils;

pub use errors::{OnewayError, Result};
pub use keypair::KeyPair;
pub use license::{create_license_token, parse_license_token, LicensePayload};
pub use response::Response;
pub use state::{load_state, save_state, StateData};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");