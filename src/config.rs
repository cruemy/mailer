use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURACION PERSISTENTE (archivo config.json)
// ═══════════════════════════════════════════════════════════════════════════
// Guarda preferencias del usuario entre ejecuciones. Por ahora solo
// guarda el display name (nombre visible). El archivo se almacena en
// el directorio de configuracion del SO:
//   - Linux:   ~/.config/sesame/config.json
//   - macOS:   ~/Library/Application Support/sesame/config.json
//   - Windows: %APPDATA%/sesame/config.json
// ═══════════════════════════════════════════════════════════════════════════

/// Estructura de la configuracion guardada en disco.
///
/// Campos
/// * `display_name` — nombre visible que eligio el usuario (opcional).
///   Si es `None`, el peer se muestra por su PeerId (hash hex).
///
/// Por que Option<String> y no String
/// Para diferenciar entre "el usuario no puso nombre" (None)
/// y "el usuario puso nombre vacio" (Some("")).
#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub display_name: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Json(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error: {e}"),
            ConfigError::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

/// Devuelve la ruta al archivo de configuracion.
///
/// Ruta tipica
/// `~/.config/sesame/config.json`
///
/// Por que no usamos un argumento CLI
/// Para que la configuracion sea automatica y el usuario no tenga que
/// acordarse de pasar la ruta cada vez. El display name persiste
/// entre ejecuciones sin intervencion.
///
/// Panic
/// Hace panic si no se puede determinar el directorio de configuracion
/// (esto basicamente nunca pasa en sistemas normales).
pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().expect("config directory not found");
    base.join("sesame").join("config.json")
}

/// Carga la configuracion desde el archivo en disco.
///
/// Que hace
/// 1. Lee el archivo en `config_path()`
/// 2. Parsea el JSON como `Config`
/// 3. Si algo falla (archivo no existe, JSON invalido), devuelve
///    `Config::default()` (display_name = None)
///
/// Por que no propagar errores
/// Porque la configuracion no es critica. Si no se puede cargar,
/// usamos valores por defecto y el programa funciona igual.
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

/// Guarda la configuracion en el archivo en disco.
///
/// Que hace
/// 1. Crea el directorio padre si no existe
/// 2. Serializa `Config` a JSON pretty-printed
/// 3. Escribe al archivo
///
/// Cada paso devuelve error al caller. La configuracion no es critica,
/// pero quien llama decide como advertir al usuario.
pub fn save_config(config: &Config) -> Result<(), ConfigError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io(e.to_string()))?;
    }
    let data =
        serde_json::to_string_pretty(config).map_err(|e| ConfigError::Json(e.to_string()))?;
    let mut file = std::fs::File::create(&path).map_err(|e| ConfigError::Io(e.to_string()))?;
    file.write_all(data.as_bytes())
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    Ok(())
}

/// Establece el display name, lo guarda en disco, y devuelve el Config actualizado.
///
/// Flujo
/// 1. Carga la config actual
/// 2. Setea display_name al nuevo valor
/// 3. Guarda a disco
/// 4. Devuelve el Config (para que el caller tenga el nombre actualizado)
///
/// Parametros
/// * `name` — el nuevo display name
///
/// Devuelve
/// El Config completo con el display name ya seteado.
pub fn set_display_name(name: &str) -> Result<Config, ConfigError> {
    let mut config = load_config();
    config.display_name = Some(name.to_string());
    save_config(&config)?;
    Ok(config)
}
