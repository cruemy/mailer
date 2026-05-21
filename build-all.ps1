param(
  [string]$Version = ""
)

if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
  Write-Error "Rust not found — install from https://rustup.rs"
  exit 1
}

if (-not (Get-Command "cargo-zigbuild" -ErrorAction SilentlyContinue)) {
  Write-Host "Installing cargo-zigbuild..."
  cargo install cargo-zigbuild
}

$Targets = @(
  "x86_64-pc-windows-msvc"
  "x86_64-unknown-linux-gnu"
  "aarch64-apple-darwin"
)

foreach ($t in $Targets) {
  Write-Host "=== Building $t ==="
  cargo zigbuild --release --target $t
  if ($LASTEXITCODE -ne 0) { exit 1 }
}

$Dist = "target/dist"
New-Item -ItemType Directory -Path $Dist -Force | Out-Null

foreach ($t in $Targets) {
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
