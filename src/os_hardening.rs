/// Aplica todas las medidas de hardening (endurecimiento) del sistema
/// operativo para proteger los secretos en memoria.
///
/// Esto se llama UNA SOLA VEZ al inicio del programa, antes de hacer
/// cualquier otra cosa. La idea es reducir al minimo las formas en
/// que un atacante podria extraer las claves de la RAM.
///
/// Que hace
/// 1. Desactiva los core dumps (volcados de memoria por crash)
/// 2. Desactiva la capacidad de hacer ptrace (debugging) del proceso
///
/// Por que es necesario
/// Si el programa crashea, el OS podria guardar toda la RAM en un
/// archivo (core dump). Ese archivo contiene las claves de cifrado.
/// Lo mismo si alguien hace `gdb -p <pid>` para inspeccionar la
/// memoria del proceso en vivo.
pub fn apply_process_hardening() {
    disable_core_dumps();
    disable_ptrace_dumping();
    check_mlock_limit();
}

/// Desactiva los core dumps usando setrlimit.
///
/// Como funciona
/// Le decimos al kernel que el tamaño maximo de core dump es 0.
/// Si el proceso crashea, no se genera ningun archivo con la memoria.
///
/// Por que solo Unix
/// En Windows los core dumps se manejan diferente (WER, Windows Error
/// Reporting) y no hay una API portable simple para desactivarlos.
///
/// Seguridad
/// RLIMIT_CORE = 0 es una practica estandar en software criptografico.
/// OpenSSH, GPG, Signal, todos lo hacen.
#[cfg(unix)]
fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to disable core dumps");
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

/// Desactiva que otros procesos puedan hacer ptrace (debug) de este
/// proceso usando prctl PR_SET_DUMPABLE = 0.
///
/// Que previene
/// - Que alguien con acceso al sistema haga `gdb -p <PID>` para leer
///   la memoria del proceso
/// - Que se generen core dumps (es otra forma de controlar lo mismo)
///
/// Por que solo Linux
/// `prctl` es una llamada al sistema de Linux. En macOS se usaria
/// `ptrace(PT_DENY_ATTACH)`, en Windows hay otras APIs. Por ahora
/// solo cubrimos Linux que es el caso mas comun en entornos de
/// produccion y servidores.
///
/// Seguridad
/// PR_SET_DUMPABLE = 0 es usado por navegadores (Chrome, Firefox)
/// y herramientas criptograficas para proteger la memoria del proceso.
#[cfg(target_os = "linux")]
fn disable_ptrace_dumping() {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to disable process dumpability");
    }
}

/// En macOS, `PT_DENY_ATTACH` evita que otros procesos se adjunten con
/// un debugger al proceso actual.
#[cfg(target_os = "macos")]
fn disable_ptrace_dumping() {
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, 0, 0) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to deny debugger attach on macOS");
    }
}

/// Windows no ofrece una API simple y portable dentro del proceso para
/// desactivar core dumps. Ese endurecimiento depende de configuracion
/// externa (WER, Group Policy, políticas de crash dump o controles del
/// sistema). Se deja como stub para documentar la limitacion sin fallar.
#[cfg(windows)]
fn disable_ptrace_dumping() {}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn disable_ptrace_dumping() {}

/// Verifica si el limite de memoria bloqueada es razonable para secretos.
///
/// Si el limite es bajo, no abortamos: solo advertimos porque el sistema
/// operativo o el contenedor pueden imponer restricciones externas.
#[cfg(unix)]
fn check_mlock_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    if rc != 0 {
        eprintln!("[sesame] warning: failed to read RLIMIT_MEMLOCK");
        return;
    }

    if limit.rlim_cur < 4096 {
        eprintln!(
            "[sesame] warning: RLIMIT_MEMLOCK is low ({} bytes); locked secrets may fail on this system",
            limit.rlim_cur
        );
    }
}

#[cfg(not(unix))]
fn check_mlock_limit() {}
