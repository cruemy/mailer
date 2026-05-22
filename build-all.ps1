<#
.SYNOPSIS
  Compila Sesame para Windows, Linux y macOS, y genera archivos .tar.gz.

.DESCRIPTION
  Este script automatiza el build cruzado de Sesame usando cargo-zigbuild.
  Genera binarios para:
    - x86_64-pc-windows-msvc (Windows 64 bits)
    - x86_64-unknown-linux-gnu (Linux 64 bits)
    - aarch64-apple-darwin (Apple Silicon / M1-M4)

  Despues de compilar, empaqueta cada binario en un .tar.gz dentro de target/dist/.

  Requiere:
    - Rust (cargo) instalado
    - cargo-zigbuild (se instala automaticamente si no existe)

.PARAMETER Version
  Version opcional para incluir en los nombres de los archivos.
  Ejemplo: .\build-all.ps1 -Version "0.2.0"
#>
param(
  [string]$Version = ""
)

# Verificar que cargo existe
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
  Write-Error "Rust not found — install from https://rustup.rs"
  exit 1
}

# Instalar cargo-zigbuild si no esta
if (-not (Get-Command "cargo-zigbuild" -ErrorAction SilentlyContinue)) {
  Write-Host "Installing cargo-zigbuild..."
  cargo install cargo-zigbuild
}

# Lista de targets (sistemas operativos destino)
$Targets = @(
  "x86_64-pc-windows-msvc"
  "x86_64-unknown-linux-gnu"
  "aarch64-apple-darwin"
)

# Compilar para cada target
foreach ($t in $Targets) {
  Write-Host "=== Building $t ==="
  cargo zigbuild --release --target $t
  if ($LASTEXITCODE -ne 0) { exit 1 }
}

# Empaquetar cada binario en .tar.gz
$Dist = "target/dist"
New-Item -ItemType Directory -Path $Dist -Force | Out-Null

foreach ($t in $Targets) {
  # En Windows los binarios terminan en .exe
  $ext = if ($t.Contains("windows")) { ".exe" } else { "" }
  $bin = "target/$t/release/sesame$ext"
  if (Test-Path $bin) {
    $archive = "sesame-$t.tar.gz"
    $dest = Join-Path $Dist $archive
    Write-Host "Packaging $archive ..."
    & tar czf $dest -C "target/$t/release" "sesame$ext"
  }
}

Write-Host "Done! Archives in target/dist/"
Get-ChildItem target/dist
