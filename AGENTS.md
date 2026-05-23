# Repository Structure for AI Agents

This file helps AI agents understand where to find project documentation and plans.

## `docs/` — User-facing documentation

- `USAGE.md` — CLI reference, connection scenarios, firewall troubleshooting
- `SECURITY.md` — threat model, security guarantees, operational limits
- `AUDIT.md` — external audit scope and release gates

## `plans/` — Technical design documents

Plans use code names that describe the feature or goal. Each plan has a clear scope, architecture decisions, and implementation roadmap.

Current plans:
- `Genesis.md` — Complete technical plan for the Sesame P2P chat MVP
- `Turris.md` — Discovery LAN + chats múltiples por conexión
- `Evangelium.md` — Discovery LAN + chats múltiples con frase por conexión
- `Nomen.md` — Persistencia del display name
- `.sisyphus/plans/Purgatio.md` — Correcciones y mejoras de seguridad

### Convención de Nombres

- Regla: una palabra, en latín, bíblica, llamativa.
- Ejemplos actuales: `Genesis`, `Turris`, `Evangelium`, `Nomen`, `Purgatio`.
- Prohibido: nombres descriptivos largos, técnicos o con múltiples palabras.

## Criterios de Creación de Planes

Todos los planes técnicos de este repositorio deben cumplir los siguientes criterios. Un plan que no los cumple se rechaza automáticamente. Estos criterios existen para que los agentes de ejecución no tengan que adivinar, interpretar o improvisar. Cada task debe ser autocontenida, verificable y libre de ambigüedad.

### Precisión Máxima

Cada task debe especificar:

- **Archivo exacto**: ruta relativa desde la raíz del repositorio.
- **Líneas aproximadas**: rango donde vive el código a modificar.
- **Función o struct**: nombre del símbolo que se toca.
- **Comportamiento esperado**: descrito en términos matemáticos o lógicos, nunca en términos subjetivos.

**Prohibido**: "mejorar", "arreglar", "optimizar", "refactorizar" sin decir qué, dónde y cómo.

**Obligatorio**: cada task debe incluir una sección de Evidence con pasos concretos para verificar el cambio.

### Acceptance Criteria Obligatorios

Cada task debe listar mínimo 3 criterios de aceptación en formato checklist:

```
- [ ] Criterio 1: qué funcionalidad se espera que funcione
- [ ] Criterio 2: qué NO debe ocurrir como consecuencia del cambio
- [ ] Criterio 3: cómo verificarlo manualmente o con un comando
```

Sin acceptance criteria, el task no está definido.

### Definition of Done (DoD)

Un task no se considera completo hasta que se cumplen los 7 pasos siguientes:

1. El código compila sin errores (`cargo check` exit 0, o equivalente en el lenguaje del proyecto).
2. Todos los tests existentes pasan (`cargo test` ALL pass, o equivalente).
3. Se agregaron tests nuevos que cubren el cambio introducido.
4. Se hizo un manual code review del diff antes de confirmar.
5. Se actualizó la documentación relevante (`docs/`, `README.md`, comentarios inline).
6. Se verificó que no hay nuevos warnings del compilador o linter.
7. Se validó que no hay regresiones en funcionalidad existente.

### Evidence Verificable

Cada task debe incluir una subsección `Evidence` con:

- Comandos exactos para compilar y testear.
- Pasos manuales para reproducir el comportamiento esperado.
- Salidas esperadas (stdout, archivos generados, estados de UI).

Si no se puede verificar, no se puede ejecutar.

### Final Verification Wave

Antes de marcar cualquier plan como completo, deben ejecutarse obligatoriamente las 4 fases de verificación final:

- **F1 — Oracle (seguridad)**: revisa todos los cambios que tocan criptografía, red o manejo de secretos.
- **F2 — Oracle (código)**: revisa calidad, idioms del lenguaje y legibilidad.
- **F3 — Build + Test + Clippy**: `cargo check`, `cargo test`, `cargo clippy` (o equivalentes) pasan limpio.
- **F4 — Momus (plan critic)**: verifica que cada task cumplió su DoD y que no quedó trabajo pendiente.

Ninguna fase es opcional. Si una falla, el plan no se cierra.

### Prohibición de Vaguedad

Un plan con descripciones vagas se rechaza automáticamente. No se negocia. No se "interpreta con buena fe". Se devuelve al autor para que reescriba el task con precisión absoluta.

**Ejemplo práctico:**

- **Mal escrito**: `Task: Arreglar F12`
  - No dice qué archivo, qué línea, qué comportamiento esperado, cómo verificar.

- **Bien escrito**: `Task: F12 — Cambiar a panic shutdown completo. En src/main.rs línea 395 reemplazar break Ok(()) por restore_terminal() + exit(0). En src/session.rs línea 275 eliminar la regeneración de certificado. Evidence: compilar, ejecutar, presionar F12, verificar que el proceso termina con exit code 0 y no queda ningún hilo activo.`
  - Archivo exacto, línea aproximada, cambio concreto, verificación clara.

### Referencia

El plan `.sisyphus/plans/Purgatio.md` cumple estos criterios y puede usarse como plantilla. Cada task de ese plan incluye archivos, líneas, comportamiento actual vs. esperado, acceptance criteria y evidence.
