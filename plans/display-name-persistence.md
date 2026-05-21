# Plan: Persistencia del Display Name

## 1. Problema

El flag `--display-name "Nombre"` funciona para la sesión actual (el peer recibe el nombre),
pero el archivo de config no se guarda. En la siguiente ejecución, el display name se pierde.

### Síntomas

- `--display-name "Pepe"` → el peer ve "Pepe" ✓
- `--display-name "Pepe"` + `cat %APPDATA%/sesame/config.json` → vacío o archivo no existe ✗
- Ejecución sin `--display-name` → no carga nada ✗

### Flujo actual

```
main()
  └─ cli_display_name = Some("Pepe")   ← argumento parseado
  └─ set_display_name("Pepe")
       ├─ load_config()                  ← intenta leer (falla silenciosamente → default)
       ├─ config.display_name = "Pepe"
       ├─ save_config(&config)
       │    ├─ create_dir_all(parent)    ← falla? → let _ =  (SILENCIO)
       │    ├─ to_string_pretty(config)  ← falla? → if let Ok =  (SILENCIO)
       │    └─ write(path, data)         ← falla? → let _ =  (SILENCIO)
       └─ return config                  ← con display_name = Some("Pepe")
  └─ SessionManager.new(display_name)   ← funciona porque el Config se devuelve en RAM
  └─ peer.connect()
       └─ send display name             ← el peer lo recibe ✓
```

**El bug es claro**: `save_config` no propaga errores. La función `set_display_name` siempre
devuelve el `Config` correcto en RAM, pero el archivo en disco nunca se escribe. El error
se traga literalmente con `let _ =`.

## 2. Root Cause — ¿Por qué Windows no escribe?

Hay múltiples causas potenciales. El plan cubre todas con contramedidas específicas.

| Causa | Probabilidad | Síntoma |
|---|---|---|
| **`dirs::config_dir()` retorna path con espacios o UTF-16** | Baja | `create_dir_all` falla |
| **AppData redirigido por GPO a path de red** | Media | `write` falla por latencia/permisos |
| **Antivirus/Defender bloquea write a `%APPDATA%\sesame\`** | Baja | `write` devuelve `AccessDenied` |
| **Write no hace flush síncrono (cierre abrupto)** | Media | Archivo truncado/inexistente |
| **Race condition: TUI loop escribe stderr que compite con stdout** | Muy baja | No aplica |
| **El usuario no reconstruyó el binario** | Alta | Código viejo |

## 3. Estrategia de Solución

### 3.1. Hacer que `save_config` retorne `Result`

```rust
pub fn save_config(config: &Config) -> Result<(), String>
```

Esto rompe la cadena de silencio. El caller decide qué hacer con el error.

### 3.2. Hacer que `set_display_name` retorne `Result<Config, String>`

```rust
pub fn set_display_name(name: &str) -> Result<Config, String>
```

### 3.3. En main.rs: abortar si no se puede guardar

```rust
let display_name = if let Some(ref name) = cli_display_name {
    match config::set_display_name(name) {
        Ok(cfg) => {
            eprintln!("[sesame] display name '{name}' saved to {}",
                config::config_path().display());
            cfg.display_name
        }
        Err(e) => {
            eprintln!("[sesame] FATAL: could not save display name: {e}");
            eprintln!("[sesame] config path: {}", config::config_path().display());
            std::process::exit(1);
        }
    }
} else {
    config::load_config().display_name
};
```

### 3.4. Sistema de rutas con fallback

Probar rutas en orden hasta que una funcione:

1. `dirs::config_dir()/sesame/config.json` — ruta estándar
2. `dirs::data_dir()/sesame/config.json` — fallback
3. `dirs::home_dir()/.sesame/config.json` — fallback final

```rust
pub fn available_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(base) = dirs::config_dir() {
        paths.push(base.join("sesame").join("config.json"));
    }
    if let Some(base) = dirs::data_dir() {
        paths.push(base.join("sesame").join("config.json"));
    }
    if let Some(base) = dirs::home_dir() {
        paths.push(base.join(".sesame").join("config.json"));
    }
    paths
}
```

Primero se intenta leer desde cualquier ruta existente. Si hay display name guardado
en alguna, se usa esa ruta como primaria. Si no, se usa la primera ruta disponible
como primaria.

### 3.5. Write atómico en Windows

Escribir a un archivo temporal y luego renombrar para evitar truncamiento:

```rust
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data)
        .map_err(|e| format!("write tmp failed: {e}"))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename failed: {e}"))?;
    Ok(())
}
```

### 3.6. Flag `--print-config-path`

Agregar un flag que solo imprime la ruta del config y sale, para debuggear:

```
sesame --print-config-path
> C:\Users\sopor\AppData\Roaming\sesame\config.json
```

## 4. Archivos a modificar

### `src/config.rs`

- `save_config` → retorna `Result<(), String>`
- `set_display_name` → retorna `Result<Config, String>`
- Nueva función `available_paths()` → retorna `Vec<PathBuf>`
- Nueva función `find_config_path()` → encuentra ruta existente o usa primera disponible
- `load_config` → probar múltiples rutas
- Nueva función `atomic_write()`

### `src/main.rs`

- Líneas 145-156: manejar `Result` de `set_display_name` con aborto
- Agregar flag `--print-config-path`
- Mostrar ruta del config en el mensaje de error

### `docs/USAGE.md`

- Documentar `--print-config-path`
- Documentar `--display-name`

## 5. Pruebas

### Manuales

```
# Test 1: creación inicial
cargo run -- --phrase test --display-name "Alice" &
# Salida: [sesame] display name 'Alice' saved to C:\Users\...\config.json
# Verificar: cat %APPDATA%\sesame\config.json → {"display_name":"Alice"}
# Cerrar con Esc

# Test 2: persistencia
cargo run -- --phrase test &
# Salida: [sesame] loaded display name 'Alice' from C:\Users\...\config.json
# El TUI debe mostrar "Alice" como display name propio

# Test 3: actualización
cargo run -- --phrase test --display-name "Bob" &
# Salida: [sesame] display name 'Bob' saved to ...
# Verificar: cat %APPDATA%\sesame\config.json → {"display_name":"Bob"}

# Test 4: --print-config-path
cargo run -- --print-config-path
# Salida: C:\Users\sopor\AppData\Roaming\sesame\config.json

# Test 5: múltiples peers — verificar que display name se recibe
# (prueba manual con dos terminales)
```

### Automatizadas

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn save_and_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        // ... test con ruta custom
    }

    #[test]
    fn atomic_write_creates_file() {
        // ...
    }
}
```

## 6. Dependencias

- `tempfile` (dev-dependency) — para tests con archivos temporales
- `dirs` — ya incluido

## 7. Checklist de Implementación

- [ ] `save_config` retorna `Result<(), String>`
- [ ] `set_display_name` retorna `Result<Config, String>`
- [ ] main.rs maneja el error con aborto
- [ ] `available_paths()` con fallback
- [ ] `find_config_path()` con multi-ruta
- [ ] `load_config()` multi-ruta
- [ ] `atomic_write()` para evitar truncamiento
- [ ] Flag `--print-config-path`
- [ ] Tests unitarios
- [ ] Verificación manual en Windows
- [ ] Build: `cargo build` sin warnings
- [ ] Tests: `cargo test` pasa
