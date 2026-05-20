# md_to_docx.ps1
# Converts all Documentation\*.md to .docx, rendering Mermaid blocks as embedded PNG images.
#
# Requirements (one-time install):
#   winget install JohnMacFarlane.Pandoc
#   winget install OpenJS.NodeJS
#   npm install -g @mermaid-js/mermaid-cli
#
# Usage (run from repo root):
#   .\md_to_docx.ps1
#
# Optional parameters:
#   -DocsDir   Path to folder containing .md files  (default: Documentation)
#   -OutDir    Where to write the .docx files       (default: Documentation\Word)
#
# Example with custom paths:
#   .\md_to_docx.ps1 -DocsDir "Documentation" -OutDir "C:\MyDocs\Word"

param(
    [string]$DocsDir = "Documentation",
    [string]$OutDir  = "Documentation\Word"
)

# ---------------------------------------------------------------------------
# 0. Preflight checks
# ---------------------------------------------------------------------------

# Add Pandoc to PATH for this session if it was just installed
$env:Path = "C:\Users\$env:USERNAME\AppData\Local\Pandoc;" + $env:Path

# mmdc uses Puppeteer which needs Chrome. Locate the highest installed version automatically.
$puppeteerCache = "C:\Users\$env:USERNAME\.cache\puppeteer\chrome-headless-shell"
if (Test-Path $puppeteerCache) {
    $chromeExe = Get-ChildItem $puppeteerCache -Recurse -Filter "chrome-headless-shell.exe" |
                 Sort-Object FullName -Descending | Select-Object -First 1
    if ($chromeExe) {
        $env:PUPPETEER_EXECUTABLE_PATH = $chromeExe.FullName
        Write-Host "Using Chrome: $($chromeExe.FullName)"
    }
}

$pandocExe = (Get-Command pandoc -ErrorAction SilentlyContinue)?.Source
if (-not $pandocExe) {
    $pandocExe = "C:\Users\$env:USERNAME\AppData\Local\Pandoc\pandoc.exe"
}
if (-not (Test-Path $pandocExe)) {
    Write-Error "pandoc not found. Install it with:  winget install JohnMacFarlane.Pandoc"
    exit 1
}

$mmdcCmd = "C:\Users\$env:USERNAME\AppData\Roaming\npm\mmdc.cmd"
if (-not (Test-Path $mmdcCmd)) {
    Write-Warning "mmdc (Mermaid CLI) not found. Mermaid blocks will be left as code blocks."
    Write-Warning "To install:  npm install -g @mermaid-js/mermaid-cli"
    $renderMermaid = $false
} else {
    $renderMermaid = $true
}

# ---------------------------------------------------------------------------
# 1. Prepare output directories
# ---------------------------------------------------------------------------

$OutDir  = [IO.Path]::GetFullPath($OutDir)
$imgDir  = Join-Path $OutDir "img"

New-Item -ItemType Directory -Force $OutDir  | Out-Null
New-Item -ItemType Directory -Force $imgDir  | Out-Null

Write-Host ""
Write-Host "Output directory : $OutDir"
Write-Host "Mermaid rendering: $renderMermaid"
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Process each markdown file
# ---------------------------------------------------------------------------

$mdFiles = Get-ChildItem "$DocsDir\*.md" -ErrorAction SilentlyContinue
if (-not $mdFiles) {
    Write-Error "No .md files found in '$DocsDir'."
    exit 1
}

foreach ($mdFile in $mdFiles) {

    $baseName = $mdFile.BaseName
    $outDocx  = Join-Path $OutDir "$baseName.docx"
    $tempMd   = Join-Path $OutDir "${baseName}_tmp.md"

    Write-Host "Processing: $($mdFile.Name)"

    # -----------------------------------------------------------------------
    # 2a. Read source and replace Mermaid fences with image references
    # -----------------------------------------------------------------------

    $content  = Get-Content $mdFile.FullName -Raw
    $imgIndex = 0

    if ($renderMermaid) {
        $processed = [regex]::Replace(
            $content,
            '(?s)```mermaid\r?\n(.*?)\r?\n```',
            {
                param($match)

                $mmdSource = $match.Groups[1].Value
                $imgName   = "${baseName}_mermaid_${script:imgIndex}.png"
                $imgPath   = Join-Path $imgDir $imgName
                $mmdFile   = Join-Path $imgDir "${baseName}_${script:imgIndex}.mmd"

                Set-Content $mmdFile $mmdSource -Encoding utf8

                # Render — white background, wide canvas for long diagrams
                $mmdcArgs = @(
                    "-i", $mmdFile,
                    "-o", $imgPath,
                    "-b", "white",
                    "-w", "1200"
                )
                & $mmdcCmd @mmdcArgs 2>&1 | Out-Null

                $script:imgIndex++

                if (Test-Path $imgPath) {
                    # Pandoc-compatible image reference (absolute path, forward slashes)
                    $fwdPath = $imgPath -replace '\\', '/'
                    "`n![]($fwdPath)`n"
                } else {
                    Write-Warning "  mmdc failed for diagram $($script:imgIndex - 1) in $($mdFile.Name) — keeping code block"
                    $match.Value
                }
            }
        )
    } else {
        # No mmdc — pass content through unchanged
        $processed = $content
    }

    Set-Content $tempMd $processed -Encoding utf8

    # -----------------------------------------------------------------------
    # 2b. Run Pandoc
    # -----------------------------------------------------------------------

    $pandocArgs = @(
        $tempMd,
        "-o", $outDocx,
        "--from", "markdown+smart",
        "--to", "docx",
        "--highlight-style", "tango",
        "--wrap", "none"
    )

    # If a reference.docx exists in the repo root, use it for styling
    $refDoc = Join-Path (Split-Path $PSScriptRoot) "reference.docx"
    if (-not (Test-Path $refDoc)) {
        $refDoc = Join-Path $PSScriptRoot "reference.docx"
    }
    if (Test-Path $refDoc) {
        $pandocArgs += "--reference-doc"
        $pandocArgs += $refDoc
        Write-Host "  Using reference.docx for styles"
    }

    & $pandocExe @pandocArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  -> $outDocx"
    } else {
        Write-Warning "  Pandoc returned exit code $LASTEXITCODE for $($mdFile.Name)"
    }

    # Clean up temp file
    if (Test-Path $tempMd) { Remove-Item $tempMd -Force }

    $imgIndex = 0   # reset per file
}

# ---------------------------------------------------------------------------
# 3. Clean up empty .mmd source files (keep only the PNGs)
# ---------------------------------------------------------------------------

Get-ChildItem $imgDir -Filter "*.mmd" | Remove-Item -Force

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "------------------------------------------------------"
$produced = (Get-ChildItem $OutDir -Filter "*.docx").Count
Write-Host "Done. $produced Word file(s) written to:"
Write-Host "  $OutDir"
Write-Host "------------------------------------------------------"
