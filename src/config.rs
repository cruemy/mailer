use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub display_name: Option<String>,
}

pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().expect("config directory not found");
    base.join("sesame").join("config.json")
}

pub fn load_config() -> Config {
    let path = config_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[sesame] config: could not read {}: {e}", path.display());
            return Config::default();
        }
    };
    match serde_json::from_str(&data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[sesame] config: invalid JSON at {}: {e}", path.display());
            Config::default()
        }
    }
}

pub fn save_config(config: &Config) {
    let path = config_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("[sesame] config: could not create {}: {e}", parent.display());
            return;
        }
    }
    let data = match serde_json::to_string_pretty(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[sesame] config: serialization error: {e}");
            return;
        }
    };
    if let Err(e) = std::fs::write(&path, &data) {
        eprintln!("[sesame] config: could not write {}: {e}", path.display());
    }
}

pub fn set_display_name(name: &str) -> Config {
    let mut config = load_config();
    config.display_name = Some(name.to_string());
    save_config(&config);
    config
}
