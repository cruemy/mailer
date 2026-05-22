use std::time::Duration;

use rand::Rng;

/// Genera un intervalo de tiempo aleatorio entre 3 y 7 segundos.
///
/// Esto se usa para enviar mensajes "dummy" (ficticios) a intervalos
/// impredecibles. La idea es que un atacante que mire el trafico de
/// red no pueda diferenciar cuando estas enviando un mensaje real
/// vs cuando solo estas mandando ruido para confundir.
///
/// Por que existe
///
/// Sin esto, los mensajes solo se enviarian cuando el usuario escribe
/// algo. Eso deja claro cuando hay conversacion y cuando no. Con
/// trafico constante y aleatorio, el observador externo no sabe si
/// estas hablando o no.
///
/// Por que 3 a 7 segundos
///
/// Es un rango lo suficientemente variado para que no se vea un
/// patron fijo, pero no tan largo como para que se note la diferencia
/// entre trafico real y dummy.
///
/// Devuelve
/// Un Duration de entre 3 y 7 segundos (random).
pub fn dummy_interval() -> Duration {
    let secs = rand::thread_rng().gen_range(3..=7);
    Duration::from_secs(secs)
}
