# nebaz installer for Windows - fetches the prebuilt binary from GitHub
# Releases, verifies its SHA-256 and (when the GitHub CLI is available) its
# signed build provenance, and puts it on your user PATH.
#
#   irm https://raw.githubusercontent.com/neboto/nebaz/main/install.ps1 | iex
#
# Prefer to read it before running it:
#   irm https://raw.githubusercontent.com/neboto/nebaz/main/install.ps1 -OutFile install.ps1
#   Get-Content install.ps1 | more; .\install.ps1
#
# Environment (same names as install.sh):
#   NEBAZ_VERSION      release tag to install (default: latest), e.g. v0.7.0
#   NEBAZ_INSTALL_DIR  where to put nebaz.exe (default: %LOCALAPPDATA%\Programs\nebaz)
#   NEBAZ_NO_ATTEST=1  skip the provenance check even when `gh` is present
#   GITHUB_TOKEN       lifts the anonymous API rate limit
#
# Works in Windows PowerShell 5.1 and PowerShell 7. Nothing here needs
# administrator rights: the binary goes under your profile and only your
# user PATH is changed.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is far faster without the progress bar

# Windows PowerShell 5.1 defaults to TLS 1.0/1.1; GitHub needs 1.2.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'could not enable TLS 1.2' }

$Repo = 'neboto/nebaz'
$Bin = 'nebaz'

function Write-Say([string]$Message) { Write-Host $Message }
function Stop-Install([string]$Message) { throw "error: $Message" }

# Wrapped in a function so `irm ... | iex` leaves no variables behind.
function Install-Nebaz {
    # ---- pick the target ------------------------------------------------------
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit PowerShell runs on a 64-bit OS.
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $target = 'x86_64-pc-windows-msvc' }
        'ARM64' { $target = 'aarch64-pc-windows-msvc' }
        default { Stop-Install "unsupported architecture: $arch" }
    }

    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'nebaz-install' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }

    # ---- resolve the version --------------------------------------------------
    $version = $env:NEBAZ_VERSION
    if (-not $version) {
        try {
            $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
        } catch {
            Stop-Install "could not determine the latest release ($($_.Exception.Message)); set GITHUB_TOKEN if rate limited"
        }
        $version = $latest.tag_name
        if (-not $version) { Stop-Install 'could not determine the latest release' }
    }
    if (-not $version.StartsWith('v')) { $version = "v$version" }
    # The tag is spliced into URLs below: accept only tag-shaped input.
    if ($version -notmatch '^v[A-Za-z0-9.+-]+$') { Stop-Install "refusing suspicious version string: $version" }

    $installDir = $env:NEBAZ_INSTALL_DIR
    if (-not $installDir) { $installDir = Join-Path $env:LOCALAPPDATA 'Programs\nebaz' }

    $base = "https://github.com/$Repo/releases/download/$version"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('nebaz-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        # ---- download the archive + checksum ----------------------------------
        $archive = "$Bin-$target.zip"
        $sums = "$Bin-$target.sha256"
        $note = ''
        try {
            Invoke-WebRequest -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive) -Headers $headers -UseBasicParsing
        } catch {
            if ($target -eq 'aarch64-pc-windows-msvc') {
                # Windows on ARM runs x64 binaries under emulation.
                $target = 'x86_64-pc-windows-msvc'
                $archive = "$Bin-$target.zip"
                $sums = "$Bin-$target.sha256"
                $note = ' (no native ARM64 build in this release; using the x64 build, which Windows on ARM emulates)'
                Invoke-WebRequest -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive) -Headers $headers -UseBasicParsing
            } else {
                Stop-Install "download failed: $base/$archive ($($_.Exception.Message))"
            }
        }
        Write-Say "Installing $Bin $version for $target$note"
        try {
            Invoke-WebRequest -Uri "$base/$sums" -OutFile (Join-Path $tmp $sums) -Headers $headers -UseBasicParsing
        } catch {
            Stop-Install "download failed: $base/$sums ($($_.Exception.Message))"
        }

        # ---- verify -----------------------------------------------------------
        # The .sha256 holds sha256sum-format lines ("<hash>  <name>") for every asset of this target.
        $line = Get-Content (Join-Path $tmp $sums) | Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))\s*$" } | Select-Object -First 1
        if (-not $line) { Stop-Install "no checksum for $archive in $sums" }
        $expected = ($line.Trim() -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
        if ($expected -ne $actual) { Stop-Install "checksum mismatch for $archive" }

        # ---- verify provenance (GitHub CLI, when available) -------------------
        # The .sha256 is uploaded by the same token as the archive, so it can't
        # catch a swapped asset; the attestation is signed by the release workflow.
        $attest = 'skipped'
        if ($env:NEBAZ_NO_ATTEST -eq '1') {
            $attest = 'skipped (NEBAZ_NO_ATTEST=1)'
        } elseif (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            $attest = 'skipped (install the GitHub CLI to verify build provenance)'
        } else {
            $null = & gh auth token 2>&1
            if ($LASTEXITCODE -ne 0) {
                $attest = "skipped (gh is not logged in; run 'gh auth login' to verify build provenance)"
            } else {
                $out = & gh attestation verify (Join-Path $tmp $archive) --repo $Repo 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-Say ($out | Out-String)
                    Stop-Install "build provenance verification FAILED for $archive - not installing"
                }
                $attest = "verified (signed by the release workflow of $Repo)"
            }
        }
        Write-Say "Provenance: $attest"

        # ---- install ----------------------------------------------------------
        $extract = Join-Path $tmp 'x'
        Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $extract -Force
        $exe = Join-Path $extract "$Bin.exe"
        if (-not (Test-Path $exe)) { Stop-Install "archive did not contain $Bin.exe" }
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        try {
            Copy-Item -Path $exe -Destination (Join-Path $installDir "$Bin.exe") -Force
        } catch {
            Stop-Install "could not write $installDir\$Bin.exe - is nebaz running? Close it and retry. ($($_.Exception.Message))"
        }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }

    Write-Say "Installed $installDir\$Bin.exe"

    # ---- PATH: user scope only, and only when missing -------------------------
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = @($userPath.Split(';') | Where-Object { $_ }) }
    $trimmed = $installDir.TrimEnd('\')
    $onPath = $entries | Where-Object { $_.TrimEnd('\') -ieq $trimmed }
    if (-not $onPath) {
        $newPath = ($entries + $installDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Say "Added $installDir to your user PATH (open a new terminal to pick it up)."
    }
    # Make it usable in this session too.
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $trimmed })) {
        $env:Path = "$env:Path;$installDir"
    }

    Write-Say ''
    Write-Say 'Next steps (nebaz needs the Azure CLI 2.54 or newer):'
    Write-Say '  az login'
    Write-Say '  nebaz doctor -o md   # checks proxy, certificates, az login and ARM access'
    Write-Say "  $Bin                  # start the browser (Windows Terminal recommended)"
}

Install-Nebaz
