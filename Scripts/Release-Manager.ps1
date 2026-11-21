param(
    [string]$RepoOwner = "Yoqaizo",
    [string]$RepoName  = "AionToolLite"
)

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Step([string]$Msg) {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  $Msg" -ForegroundColor White
    Write-Host "==========================================================" -ForegroundColor Cyan
}

function Write-Ok([string]$Msg)   { Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn([string]$Msg) { Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Err([string]$Msg)  { Write-Host "[ERROR] $Msg" -ForegroundColor Red }

function Read-TextUtf8([string]$Path) {
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}

function Write-TextUtf8([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Find-Iscc {
    $cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # 1. Check standard installation paths (Inno Setup 7, 6, 5)
    $candidates = @()
    foreach ($ver in @("7", "6", "5")) {
        if ($env:ProgramFiles) {
            $candidates += (Join-Path $env:ProgramFiles "Inno Setup $ver\ISCC.exe")
        }
        if (${env:ProgramFiles(x86)}) {
            $candidates += (Join-Path ${env:ProgramFiles(x86)} "Inno Setup $ver\ISCC.exe")
        }
        if ($env:LOCALAPPDATA) {
            $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup $ver\ISCC.exe")
        }
    }

    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
    }

    # 2. Check Windows Uninstall Registry (finds Inno Setup on any custom drive/folder)
    $regRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $regRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($keyName in @("Inno Setup 7_is1", "Inno Setup 6_is1", "Inno Setup 5_is1")) {
            $rp = Join-Path $root $keyName
            if (Test-Path $rp) {
                $loc = (Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue).InstallLocation
                if (-not [string]::IsNullOrWhiteSpace("$loc")) {
                    $exe = Join-Path ("$loc".Trim()) "ISCC.exe"
                    if (Test-Path -LiteralPath $exe -PathType Leaf) { return $exe }
                }
            }
        }
    }

    # 3. Interactive fallback if installed in a portable/custom folder
    Write-Warn "ISCC.exe was not found automatically."
    $manual = Read-Host "Drag and drop ISCC.exe (or Inno Setup folder) here and press ENTER"
    if (-not [string]::IsNullOrWhiteSpace($manual)) {
        $clean = $manual.Trim().Trim([char]34)
        if (Test-Path -LiteralPath $clean -PathType Container) { $clean = Join-Path $clean "ISCC.exe" }
        if (Test-Path -LiteralPath $clean -PathType Leaf) { return $clean }
    }
    return $null
}

# ==================== 1. READ AND OPTIONALLY BUMP VERSION ====================
$CsprojPath = Join-Path $RootDir "AionToolLite\AionToolLite.csproj"
if (-not (Test-Path -LiteralPath $CsprojPath)) {
    Write-Err "Could not find $CsprojPath"
    exit 1
}

$csprojText = Read-TextUtf8 $CsprojPath
if ($csprojText -notmatch '<Version>(\d+\.\d+\.\d+)</Version>') {
    Write-Err "Could not parse <Version> from AionToolLite.csproj"
    exit 1
}
$CurrentVer = $Matches[1]

Write-Step "AionToolLite GitHub Release and Version Manager"
Write-Host "  Repository      : https://github.com/$RepoOwner/$RepoName" -ForegroundColor Gray
Write-Host "  Current Version : v$CurrentVer" -ForegroundColor Green
Write-Host ""

$InputVer = Read-Host "Press ENTER to publish v$CurrentVer, or type a new version (e.g. 1.2.3)"
$TargetVer = if ([string]::IsNullOrWhiteSpace($InputVer)) { $CurrentVer } else { $InputVer.Trim().TrimStart('v', 'V') }

if ($TargetVer -notmatch '^\d+\.\d+\.\d+$') {
    Write-Err "Invalid version format '$TargetVer'. Expected MAJOR.MINOR.PATCH (e.g. 1.2.2)."
    exit 1
}

if ($TargetVer -ne $CurrentVer) {
    Write-Step "Syncing Version Across All Project Files: $CurrentVer -> $TargetVer"

    # AionToolLite.csproj
    $txt = Read-TextUtf8 $CsprojPath
    $txt = [regex]::Replace($txt, '<Version>\d+\.\d+\.\d+</Version>', "<Version>$TargetVer</Version>")
    $txt = [regex]::Replace($txt, '<AssemblyVersion>\d+\.\d+\.\d+\.\d+</AssemblyVersion>', "<AssemblyVersion>$TargetVer.0</AssemblyVersion>")
    $txt = [regex]::Replace($txt, '<FileVersion>\d+\.\d+\.\d+\.\d+</FileVersion>', "<FileVersion>$TargetVer.0</FileVersion>")
    Write-TextUtf8 $CsprojPath $txt

    # app.manifest
    $manifestPath = Join-Path $RootDir "AionToolLite\app.manifest"
    $txt = Read-TextUtf8 $manifestPath
    $txt = [regex]::Replace($txt, 'assemblyIdentity version="\d+\.\d+\.\d+\.\d+"', "assemblyIdentity version=`"$TargetVer.0`"")
    Write-TextUtf8 $manifestPath $txt

    # AionToolLite_Installer.iss
    $issPath = Join-Path $RootDir "AionToolLite_Installer.iss"
    $txt = Read-TextUtf8 $issPath
    $txt = [regex]::Replace($txt, '#define AppVer "\d+\.\d+\.\d+"', "#define AppVer `"$TargetVer`"")
    Write-TextUtf8 $issPath $txt

    # MainWindow.xaml footer fallback
    $mwXamlPath = Join-Path $RootDir "AionToolLite\MainWindow.xaml"
    $txt = Read-TextUtf8 $mwXamlPath
    $txt = [regex]::Replace($txt, 'AionToolLite v\d+\.\d+\.\d+', "AionToolLite v$TargetVer")
    Write-TextUtf8 $mwXamlPath $txt

    # README.md badges and setup filename
    $readmePath = Join-Path $RootDir "README.md"
    if (Test-Path -LiteralPath $readmePath) {
        $txt = Read-TextUtf8 $readmePath
        $txt = [regex]::Replace($txt, 'Version-v\d+\.\d+\.\d+', "Version-v$TargetVer")
        $txt = [regex]::Replace($txt, 'AionToolLite_Setup_v\d+\.\d+\.\d+\.exe', "AionToolLite_Setup_v$TargetVer.exe")
        Write-TextUtf8 $readmePath $txt
    }

    # Batch scripts titles
    foreach ($batName in @("Build-Release-Exe.bat", "Publish-Standalone-Exe.bat", "Run-As-Admin.bat")) {
        $bp = Join-Path $RootDir $batName
        if (Test-Path -LiteralPath $bp) {
            $txt = Read-TextUtf8 $bp
            $txt = [regex]::Replace($txt, 'AionToolLite \d+\.\d+\.\d+', "AionToolLite $TargetVer")
            Write-TextUtf8 $bp $txt
        }
    }

    Write-Ok "All project files synced to v$TargetVer."
    Write-Warn "Remember to update RELEASE_NOTES.md if you want custom changelog text for v$TargetVer."
}

$TagName = "v$TargetVer"

# ==================== 2. CHECK PREREQUISITES ====================
Write-Step "Checking Required Tools (dotnet, git, gh, Inno Setup)"

foreach ($tool in @("dotnet", "git", "gh")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Err "Required tool '$tool' was not found in PATH."
        if ($tool -eq "gh") {
            Write-Host "Install GitHub CLI easily by running:  winget install --id GitHub.cli -e --source winget" -ForegroundColor Yellow
            Write-Host "Or download from: https://cli.github.com/" -ForegroundColor Yellow
        } elseif ($tool -eq "git") {
            Write-Host "Install Git from: https://git-scm.com/download/win" -ForegroundColor Yellow
        } elseif ($tool -eq "dotnet") {
            Write-Host "Install .NET 8 SDK from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        }
        exit 1
    }
    Write-Ok "$tool found."
}

$IsccExe = Find-Iscc
if (-not $IsccExe) {
    Write-Err "Inno Setup Compiler (ISCC.exe) not found! Please install Inno Setup 6 or 7 from https://jrsoftware.org/isinfo.php"
    exit 1
}
Write-Ok "Inno Setup found: $IsccExe"

# ==================== 3. GITHUB AUTH (SAFE BROWSER LOGIN) ====================
Write-Step "Verifying GitHub CLI Authentication"
$null = & gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warn "You are not logged in to GitHub CLI yet. Opening secure browser login..."
    & gh auth login --web --git-protocol https
    if ($LASTEXITCODE -ne 0) {
        Write-Err "GitHub authentication failed."
        exit 1
    }
}
Write-Ok "Authenticated with GitHub CLI."

$null = & gh auth setup-git 2>&1

# ==================== 4. BUILD STANDALONE EXE AND INSTALLER ====================
Write-Step "Publishing Standalone Single-File AionToolLite.exe (v$TargetVer)"
& dotnet publish "AionToolLite\AionToolLite.csproj" -c Release -r win-x64 --self-contained true `
    /p:PublishSingleFile=true /p:PublishReadyToRun=true /p:EnableCompressionInSingleFile=true `
    /p:DebugType=None /p:DebugSymbols=false
if ($LASTEXITCODE -ne 0) {
    Write-Err "dotnet publish failed."
    exit 1
}
Write-Ok "Standalone executable built successfully."

Write-Step "Compiling Inno Setup Installer (AionToolLite_Setup_v$TargetVer.exe)"
& $IsccExe "/DAppVer=$TargetVer" (Join-Path $RootDir "AionToolLite_Installer.iss")
if ($LASTEXITCODE -ne 0) {
    Write-Err "Inno Setup compilation failed."
    exit 1
}

$InstallerExe = Join-Path $RootDir "Installer\AionToolLite_Setup_v$TargetVer.exe"
if (-not (Test-Path -LiteralPath $InstallerExe)) {
    Write-Err "Expected installer not found at: $InstallerExe"
    exit 1
}
Write-Ok "Installer created: $InstallerExe"

# ==================== 5. GENERATE SHA256 CHECKSUMS.TXT ====================
Write-Step "Generating SHA256 checksums.txt"
$HashHex = (Get-FileHash -Path $InstallerExe -Algorithm SHA256).Hash.ToLowerInvariant()
$ChecksumPath = Join-Path $RootDir "Installer\checksums.txt"
$ChecksumLine = "$HashHex  AionToolLite_Setup_v$TargetVer.exe`r`n"
Write-TextUtf8 $ChecksumPath $ChecksumLine
Write-Ok "SHA256: $HashHex"

# ==================== 6. GIT INIT / COMMIT / PUSH ====================
Write-Step "Syncing Source Code to GitHub ($RepoOwner/$RepoName)"

$IsFreshGitRepo = -not (Test-Path -LiteralPath (Join-Path $RootDir ".git"))
if ($IsFreshGitRepo) {
    & git init
    if ($LASTEXITCODE -ne 0) {
        Write-Err "git init failed."
        exit 1
    }
    Write-Ok "Initialized new Git repository."
}

$gitName = ((& git config user.name 2>$null) -join "").Trim()
$gitEmail = ((& git config user.email 2>$null) -join "").Trim()
if ([string]::IsNullOrWhiteSpace($gitName)) {
    & git config user.name $RepoOwner
}
if ([string]::IsNullOrWhiteSpace($gitEmail)) {
    & git config user.email "$RepoOwner@users.noreply.github.com"
}

$RemoteUrl = "https://github.com/$RepoOwner/$RepoName.git"
$remotes = @(& git remote 2>$null)
if ($remotes -notcontains "origin") {
    & git remote add origin $RemoteUrl
} else {
    & git remote set-url origin $RemoteUrl
}

# Create public repository automatically if it does not exist yet
$null = & gh repo view "$RepoOwner/$RepoName" 2>&1
$RepoAlreadyExisted = ($LASTEXITCODE -eq 0)
if (-not $RepoAlreadyExisted) {
    Write-Warn "Repository $RepoOwner/$RepoName does not exist yet. Creating public repository..."
    & gh repo create "$RepoOwner/$RepoName" --public --description "A sleek, hardened, one-tap Windows DNS, Hosts and Network Companion (.NET 8 WPF)"
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Could not create GitHub repository."
        exit 1
    }
    Write-Ok "Created public GitHub repository: https://github.com/$RepoOwner/$RepoName"
} elseif ($IsFreshGitRepo) {
    # If extracted into a fresh folder while GitHub already has commits, attach cleanly onto origin/main without losing files
    Write-Warn "Existing GitHub repository detected from a fresh folder. Syncing commit history..."
    $null = & git fetch origin main 2>&1
    $null = & git rev-parse --verify refs/remotes/origin/main 2>&1
    if ($LASTEXITCODE -eq 0) {
        & git symbolic-ref HEAD refs/heads/main
        & git update-ref refs/heads/main refs/remotes/origin/main
        Write-Ok "Attached cleanly to existing origin/main history."
    }
}

& git add -A

$statusLines = @(& git status --porcelain 2>$null)
$statusText = ($statusLines -join "`n").Trim()
if (-not [string]::IsNullOrWhiteSpace($statusText)) {
    $CommitMsg = Read-Host "Commit message (press ENTER for 'Release $TagName')"
    if ([string]::IsNullOrWhiteSpace($CommitMsg)) {
        $CommitMsg = "Release $TagName"
    }
    & git commit -m $CommitMsg
    if ($LASTEXITCODE -ne 0) {
        Write-Err "git commit failed."
        exit 1
    }
} else {
    Write-Ok "Working tree already clean - no new commit needed."
}

& git branch -M main
& git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Err "git push failed. If the remote repo already has commits (e.g. a README created on GitHub), run 'git pull --rebase origin main' first."
    exit 1
}
Write-Ok "Source code pushed to origin/main."

# ==================== 7. CREATE OR UPDATE GITHUB RELEASE ====================
Write-Step "Publishing Official GitHub Release ($TagName)"

$NotesPath = Join-Path $RootDir "RELEASE_NOTES.md"
if (-not (Test-Path -LiteralPath $NotesPath)) {
    Write-TextUtf8 $NotesPath "## AionToolLite $TagName`r`n`r`nDownload ``AionToolLite_Setup_v$TargetVer.exe`` below to install or update."
}

$null = & gh release view $TagName --repo "$RepoOwner/$RepoName" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Warn "Release $TagName already exists. Uploading updated assets and notes..."
    & gh release edit $TagName --repo "$RepoOwner/$RepoName" --title "AionToolLite $TagName" --notes-file $NotesPath --latest
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to update existing release metadata."
        exit 1
    }
    & gh release upload $TagName $InstallerExe $ChecksumPath --repo "$RepoOwner/$RepoName" --clobber
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to update existing release assets."
        exit 1
    }
} else {
    & gh release create $TagName $InstallerExe $ChecksumPath `
        --repo "$RepoOwner/$RepoName" `
        --title "AionToolLite $TagName" `
        --notes-file $NotesPath `
        --latest
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create GitHub Release $TagName."
        exit 1
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  SUCCESS! AionToolLite $TagName is now LIVE on GitHub!" -ForegroundColor Green
Write-Host "  https://github.com/$RepoOwner/$RepoName/releases/tag/$TagName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Start-Process "https://github.com/$RepoOwner/$RepoName/releases/tag/$TagName"
