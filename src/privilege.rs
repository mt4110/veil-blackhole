//! Fail-closed privilege sequence, independently testable without changing IDs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
}

pub trait DropOperations {
    fn initialize_groups(&mut self) -> Result<(), String>;
    fn set_gid(&mut self) -> Result<(), String>;
    fn set_uid(&mut self) -> Result<(), String>;
    fn verify(&mut self) -> Result<(), String>;
}

/// This token is only constructed after every requested operation succeeds.
pub struct Dropped;

pub fn drop_privileges(operations: &mut impl DropOperations) -> Result<Dropped, String> {
    operations.initialize_groups()?;
    operations.set_gid()?;
    operations.set_uid()?;
    operations.verify()?;
    Ok(Dropped)
}
