using namespace System.IO

param(
    [Parameter(Mandatory, Position = 0)]
    [DirectoryInfo]$Example,

    [Parameter(Position = 1)]
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",

    [Parameter(Position = 2)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

$language = Split-Path (Split-Path $Example -Parent) -Leaf

if ($Configuration -eq "release") {
    cargo build --bin obfuscator --release $Arguments
}
else {
    cargo build --bin obfuscator $Arguments
}

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

switch ($language) {
    "rust" {
        $manifest = Join-Path $Example.FullName "Cargo.toml"

        if ($Configuration -eq "release") {
            cargo build --manifest-path $manifest --release
        }
        else {
            cargo build --manifest-path $manifest
        }

        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        $metadata = cargo metadata `
            --manifest-path $manifest `
            --format-version 1 `
            --no-deps | ConvertFrom-Json

        $manifest = [Path]::GetFullPath($manifest)

        $package = $metadata.packages |
            Where-Object {
                [Path]::GetFullPath($_.manifest_path) -eq $manifest
            } |
            Select-Object -First 1

        $target = $package.targets |
            Where-Object { $_.kind -contains "bin" } |
            Select-Object -First 1

        $source = Join-Path `
            $metadata.target_directory `
            "$Configuration\$($target.name).exe"
    }

    "cpp" {
        $main = Join-Path $Example.FullName "main.cpp"

        $source = Join-Path `
            $Example.Parent.Parent.FullName `
            "$($Example.Name).exe"

        if ($Configuration -eq "release") {
            g++ $main -o $source -O2
        }
        else {
            g++ $main -o $source -O0 -g
        }

        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    default {
        throw "Unsupported language: $language"
    }
}

$source = [Path]::GetFullPath($source)

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Source executable not found: $source"
}

$obfuscator = Join-Path $PWD "target\$Configuration\obfuscator.exe"

& $obfuscator --virtualization -v $source

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$destination = [Path]::ChangeExtension(
    $source,
    ".protected.exe"
)

& $destination

$code = $LASTEXITCODE

Remove-Item $source -Force -ErrorAction SilentlyContinue
Remove-Item $destination -Force -ErrorAction SilentlyContinue

exit $code
