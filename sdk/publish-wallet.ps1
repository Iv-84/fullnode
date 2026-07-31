$ErrorActionPreference = 'Stop'

$sdkDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $sdkDir)
$walletJslib = Join-Path $repoRoot 'wallet\public\jslib'
$target = 'wasm32-unknown-unknown'
$profile = 'wasm-release'
$expectedBindgen = '0.2.100'
$outDir = Join-Path $sdkDir 'dist\wallet'

if (-not ((rustup target list --installed) -contains $target)) {
    throw "Rust target $target is not installed. Run: rustup target add $target"
}
$bindgen = Get-Command wasm-bindgen -ErrorAction SilentlyContinue
if (-not $bindgen) {
    throw "wasm-bindgen is not installed. Run: cargo install -f wasm-bindgen-cli --version $expectedBindgen"
}
$actualBindgen = (& wasm-bindgen --version).Split()[-1]
if ($actualBindgen -ne $expectedBindgen) {
    throw "wasm-bindgen version mismatch: expected $expectedBindgen, got $actualBindgen"
}

cargo build --manifest-path (Join-Path $sdkDir 'Cargo.toml') --target $target --profile $profile --lib
if ($LASTEXITCODE -ne 0) { throw 'SDK wasm build failed' }

$metadata = cargo metadata --manifest-path (Join-Path $sdkDir 'Cargo.toml') --format-version 1 --no-deps | ConvertFrom-Json
$wasm = Join-Path $metadata.target_directory "$target\$profile\sdk.wasm"
if (-not (Test-Path -LiteralPath $wasm)) { throw "SDK wasm output not found: $wasm" }

New-Item -ItemType Directory -Force -Path $outDir, $walletJslib | Out-Null
& wasm-bindgen $wasm --out-name hacash_sdk --out-dir $outDir --target no-modules --remove-name-section --remove-producers-section
if ($LASTEXITCODE -ne 0) { throw 'wasm-bindgen failed' }

Copy-Item -Force (Join-Path $outDir 'hacash_sdk.js') (Join-Path $walletJslib 'hacash_sdk.js')
Copy-Item -Force (Join-Path $outDir 'hacash_sdk_bg.wasm') (Join-Path $walletJslib 'hacash_sdk.wasm')

Write-Host "Published TEX-enabled SDK to $walletJslib"
