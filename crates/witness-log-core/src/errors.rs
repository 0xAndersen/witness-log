//! One umbrella error for the whole crate, so every future language
//! binding (Node, Go, ...) maps ONE shape instead of four. Each variant
//! wraps the module-specific error it came from — nothing is flattened
//! or lost, callers who want specifics still match inward.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WitnessLogError {
    #[error(transparent)]
    Sth(#[from] crate::sth::SthError),
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    #[error(transparent)]
    Verify(#[from] crate::log::VerifyError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
