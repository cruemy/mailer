<#
.SYNOPSIS
  Compila Sesame en modo release y lo instala globalmente.

.DESCRIPTION
  Script rapido para desarrollo:
  1. Compila en modo release (cargo b -r)
  2. Instala el binario globalmente (cargo install --path .)

  Despues de ejecutar esto, podes escribir "sesame" desde cualquier
  terminal en vez de tener que usar "cargo run --release".
#>
cargo b -r && cargo install --path .
