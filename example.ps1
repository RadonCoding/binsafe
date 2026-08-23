param(
    [Parameter(Mandatory)]
    [string]$Example
)

$ErrorActionPreference = "Stop"

$language = $Example.Split("/")[1]

$env:OUTPUT_DIRECTORY = "$PWD/api/generated"
$env:TEMPLATES_DIRECTORY = "$PWD/api/templates"

cargo build --package markers

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cargo build --bin obfuscator

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

switch ($language) {
    "rust" {
        cargo build --manifest-path "$Example/Cargo.toml"

        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        $metadata = cargo metadata --manifest-path "$Example/Cargo.toml" --format-version 1 --no-deps | ConvertFrom-Json

        $package = $metadata.packages[0]
        $target = $package.targets | Where-Object { $_.kind -contains "bin" } | Select-Object -First 1

        $source = Join-Path $metadata.target_directory "debug\$($target.name).exe"
    }
    "cpp" {
        g++ "$Example/main.cpp"
        
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        $source = Join-Path $PWD "a.exe"
    }
}

& "target/debug/obfuscator.exe" --virtualization $source

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$destination = [System.IO.Path]::ChangeExtension($source, ".protected.exe")

& $destination

$code = $LASTEXITCODE

Remove-Item $source -Force -ErrorAction SilentlyContinue
Remove-Item $destination -Force -ErrorAction SilentlyContinue

exit $code