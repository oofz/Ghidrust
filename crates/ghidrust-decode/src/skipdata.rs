use std::sync::Arc;

/// Skip-data callback .
pub trait SkipdataCb: Send + Sync {
    fn skip(&self, address: u64, data: &[u8]) -> usize;
}

/// Function-pointer style skip-data callback.
pub type SkipdataFn = fn(u64, *const u8, usize) -> usize;

#[derive(Clone)]
pub enum SkipdataHandler {
    None,
    Trait(Arc<dyn SkipdataCb>),
    Fn(SkipdataFn),
}

impl std::fmt::Debug for SkipdataHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipdataHandler::None => write!(f, "SkipdataHandler::None"),
            SkipdataHandler::Trait(_) => write!(f, "SkipdataHandler::Trait(_)"),
            SkipdataHandler::Fn(_) => write!(f, "SkipdataHandler::Fn(_)"),
        }
    }
}

impl Default for SkipdataHandler {
    fn default() -> Self {
        Self::None
    }
}

impl SkipdataHandler {
    pub fn invoke(&self, address: u64, data: &[u8]) -> usize {
        match self {
            SkipdataHandler::None => 1,
            SkipdataHandler::Trait(cb) => cb.skip(address, data),
            SkipdataHandler::Fn(f) => f(address, data.as_ptr(), data.len()),
        }
    }
}

/// Skip-data configuration .
#[derive(Clone, Default)]
pub struct SkipdataConfig {
    pub mnemonic: String,
    pub handler: SkipdataHandler,
}

impl SkipdataConfig {
    pub fn new(mnemonic: impl Into<String>) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            handler: SkipdataHandler::None,
        }
    }

    pub fn with_trait(mut self, cb: Arc<dyn SkipdataCb>) -> Self {
        self.handler = SkipdataHandler::Trait(cb);
        self
    }

    pub fn with_fn(mut self, f: SkipdataFn) -> Self {
        self.handler = SkipdataHandler::Fn(f);
        self
    }
}

impl std::fmt::Debug for SkipdataConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkipdataConfig")
            .field("mnemonic", &self.mnemonic)
            .field("handler", &self.handler)
            .finish()
    }
}
