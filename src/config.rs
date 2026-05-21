use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub display_name: Option<String>,
}

fn config_path() -> PathBuf {
    let base = dirs::config_dir().expect("config directory not found");
    base.join("sesame").join("config.json")
}

pub fn load_config() -> Config {
    let path = config_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

pub fn save_config(config: &Config) {
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(data) = serde_json::to_string_pretty(config) {
        let _ = std::fs::write(&path, data);
    }
}

pub fn set_display_name(name: &str) -> Config {
    let mut config = load_config();
    config.display_name = Some(name.to_string());
    save_config(&config);
    config
}
