/// Estado del modo panico.
///
/// El modo panico es una caracteristica de seguridad fisica: si alguien
/// te obliga a abrir el chat (coercion), presionas F12 y todo el
/// programa cambia a una identidad falsa. Tus mensajes anteriores y
/// tus conexiones desaparecen.
///
/// Campos
/// * `is_decoy` — si es `true`, significa que estas usando la frase
///   "señuelo" (decoy). La UI muestra un indicador ROJO diciendo
///   "PANIC MODE" para que sepas que estas en modo seguro.
///   Si es `false`, estas en modo real (frase verdadera).
pub struct PanicHandler {
    pub is_decoy: bool,
}

impl PanicHandler {
    /// Crea un nuevo PanicHandler.
    ///
    /// Parametros
    /// * `start_decoy` — si arrancamos en modo decoy o no. Viene de la
    ///   flag `--decoy` en linea de comandos.
    pub fn new(start_decoy: bool) -> Self {
        Self {
            is_decoy: start_decoy,
        }
    }
}
