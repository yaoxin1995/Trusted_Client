#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    None,
    Common(String),

}

impl Default for Error {
    fn default() -> Self {
        Error::None
    }
}