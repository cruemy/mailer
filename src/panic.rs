pub struct PanicHandler {
    pub is_decoy: bool,
}

impl PanicHandler {
    pub fn new(start_decoy: bool) -> Self {
        Self {
            is_decoy: start_decoy,
        }
    }
}
