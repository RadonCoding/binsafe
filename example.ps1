param(
    [Parameter(Mandatory)]
    [System.IO.DirectoryInfo]$Example,
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

$language = Split-Path (Split-Path $Example -Parent) -Leaf

$env:OUTPUT_DIRECTORY = Join-Path $PWD "api/generated"
$env:TEMPLATES_DIRECTORY = Join-Path $PWD "api/templates"

cargo build --package markers

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cargo build --bin obfuscator $Arguments

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

switch ($language) {
    "rust" {
        $manifest = Join-Path $Example.FullName "Cargo.toml"

        cargo build --manifest-path $manifest

        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        $metadata = cargo metadata `
            --manifest-path $manifest `
            --format-version 1 `
            --no-deps | ConvertFrom-Json

        $manifest = [System.IO.Path]::GetFullPath($manifest)

        $package = $metadata.packages |
        Where-Object {
            [System.IO.Path]::GetFullPath($_.manifest_path) -eq $manifest
        } |
        Select-Object -First 1

        $target = $package.targets |
        Where-Object { $_.kind -contains "bin" } |
        Select-Object -First 1

        $source = Join-Path `
            $metadata.target_directory `
            "debug\$($target.name).exe"
    }

    "cpp" {
        $main = Join-Path $Example.FullName "main.cpp"

        $source = Join-Path `
            $example.Parent.Parent.FullName `
            "$($example.Name).exe"

        g++ $main -o $source

        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    default {
        throw "Unsupported language: $language"
    }
}

$source = [System.IO.Path]::GetFullPath($source)

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Source executable not found: $source"
}

& (Join-Path $PWD "target/debug/obfuscator.exe") --virtualization -v $source

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$destination = [System.IO.Path]::ChangeExtension(
    $source,
    ".protected.exe"
)

& $destination

$code = $LASTEXITCODE

Remove-Item $source -Force -ErrorAction SilentlyContinue
Remove-Item $destination -Force -ErrorAction SilentlyContinue

exit $code
