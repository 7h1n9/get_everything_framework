param(
    [switch]$CheckOnly,
    [switch]$SkipSystem,
    [switch]$SkipPythonDeps,
    [switch]$SkipGoTools,
    [switch]$WithOptional,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$RequirementsFile = Join-Path $RootDir "requirement.txt"
$LocalToolsDir = Join-Path $RootDir "tools"

$WingetPackages = [ordered]@{
    "python" = "Python.Python.3"
    "go" = "GoLang.Go"
    "git" = "Git.Git"
    "nmap" = "Insecure.Nmap"
}

$GoTools = [ordered]@{
    "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "shuffledns" = "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "alterx" = "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "gospider" = "github.com/jaeles-project/gospider@latest"
    "dnsx" = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "httpx" = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "naabu" = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "waybackurls" = "github.com/tomnomnom/waybackurls@latest"
    "katana" = "github.com/projectdiscovery/katana/cmd/katana@latest"
    "assetfinder" = "github.com/tomnomnom/assetfinder@latest"
}

$ExpectedTools = @(
    "alterx", "amass", "assetfinder", "dirsearch", "dnsx", "feroxbuster",
    "gospider", "httpx", "http-x", "katana", "naabu", "nmap", "shuffledns",
    "subfinder", "waybackurls"
)

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-CommandStep {
    param([string[]]$Command)
    Write-Host "[*] $($Command -join ' ')"
    if (-not $DryRun) {
        & $Command[0] @($Command[1..($Command.Count - 1)])
    }
}

function Get-PythonCommand {
    if (Test-Command "py") {
        return "py"
    }
    if (Test-Command "python") {
        return "python"
    }
    return $null
}

function Get-GoBin {
    if ($env:GOBIN) {
        return $env:GOBIN
    }
    if (Test-Command "go") {
        $goPath = (& go env GOPATH 2>$null)
        if ($goPath) {
            return Join-Path $goPath "bin"
        }
    }
    return Join-Path $HOME "go\bin"
}

function Add-UserPath {
    param([string]$PathToAdd)
    if (-not $PathToAdd) {
        return
    }

    $currentProcessPath = [Environment]::GetEnvironmentVariable("PATH", "Process")
    if (($currentProcessPath -split ";") -notcontains $PathToAdd) {
        [Environment]::SetEnvironmentVariable("PATH", "$currentProcessPath;$PathToAdd", "Process")
    }

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if (($userPath -split ";") -contains $PathToAdd) {
        return
    }

    Write-Host "[*] Add user PATH: $PathToAdd"
    if (-not $DryRun) {
        $newPath = if ($userPath) { "$userPath;$PathToAdd" } else { $PathToAdd }
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    }
}

function Update-ProcessPathFromRegistry {
    $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    [Environment]::SetEnvironmentVariable("PATH", "$machinePath;$userPath", "Process")
}

function Resolve-ToolPath {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    return $null
}

function Ensure-HttpxAlias {
    $goBin = Get-GoBin
    $target = Join-Path $goBin "httpx.exe"
    $aliasPath = Join-Path $goBin "http-x.cmd"

    if (-not (Test-Path $target)) {
        Write-Host "[!] ProjectDiscovery httpx.exe not found at: $target"
        return
    }

    Write-Host "[*] Create http-x alias: $aliasPath"
    if (-not $DryRun) {
        @(
            "@echo off",
            "`"$target`" %*"
        ) | Set-Content -Path $aliasPath -Encoding ASCII
    }

    Add-UserPath $goBin
    Update-ProcessPathFromRegistry
}

function Get-GoToolExecutablePath {
    param([string]$ToolName)
    return Join-Path (Get-GoBin) ($ToolName + ".exe")
}

function Test-HttpxInstallation {
    $goBin = Get-GoBin
    $expectedHttpx = Join-Path $goBin "httpx.exe"
    $expectedAlias = Join-Path $goBin "http-x.cmd"
    $resolvedHttpx = Resolve-ToolPath "httpx"
    $resolvedAlias = Resolve-ToolPath "http-x"

    Write-Host "[i] Expected ProjectDiscovery httpx: $expectedHttpx"
    Write-Host "[i] where httpx => $resolvedHttpx"
    Write-Host "[i] where http-x => $resolvedAlias"

    if (-not (Test-Path $expectedHttpx)) {
        Write-Host "[!] ProjectDiscovery httpx.exe is missing."
        return $false
    }
    if (-not (Test-Path $expectedAlias)) {
        Write-Host "[!] http-x alias is missing."
        return $false
    }
    if ($resolvedAlias -ne $expectedAlias) {
        Write-Host "[!] http-x does not resolve to the expected alias path."
        return $false
    }
    if ($resolvedHttpx -and ($resolvedHttpx -ne $expectedHttpx)) {
        Write-Host "[!] httpx resolves to another executable. The project will use http-x instead."
    }

    Write-Host "[ok] ProjectDiscovery httpx alias is ready"
    return $true
}

function Install-WingetPackage {
    param(
        [string]$CommandName,
        [string]$PackageId
    )

    if (Test-Command $CommandName) {
        Write-Host "[=] $CommandName already exists in PATH"
        return
    }

    if (-not (Test-Command "winget")) {
        Write-Host "[!] winget is not available. Install $CommandName manually, then rerun this script."
        return
    }

    Invoke-CommandStep @(
        "winget", "install", "--id", $PackageId, "-e",
        "--accept-source-agreements", "--accept-package-agreements"
    )
}

function Install-SystemDependencies {
    Write-Host ""
    Write-Host "=== System dependencies ==="
    foreach ($name in $WingetPackages.Keys) {
        Install-WingetPackage $name $WingetPackages[$name]
    }

    Update-ProcessPathFromRegistry
    $goInstallDir = Join-Path $env:ProgramFiles "Go\bin"
    if (Test-Path $goInstallDir) {
        Add-UserPath $goInstallDir
        Update-ProcessPathFromRegistry
    }

    if (Test-Command "go") {
        Add-UserPath (Get-GoBin)
    }
}

function Install-PythonDependencies {
    Write-Host ""
    Write-Host "=== Python dependencies ==="
    $python = Get-PythonCommand
    if (-not $python) {
        Write-Host "[!] Python is not installed or not in PATH."
        return
    }
    if (-not (Test-Path $RequirementsFile)) {
        Write-Host "[!] Missing requirements file: $RequirementsFile"
        return
    }
    Invoke-CommandStep @($python, "-m", "pip", "install", "--upgrade", "pip")
    Invoke-CommandStep @($python, "-m", "pip", "install", "-r", $RequirementsFile)
}

function Install-Amass {
    Write-Host ""
    Write-Host "=== amass ==="
    if (Test-Command "amass") {
        Write-Host "[=] amass already exists in PATH"
        return
    }

    if (Test-Command "winget") {
        Invoke-CommandStep @(
            "winget", "install", "--id", "OWASP.Amass", "-e",
            "--accept-source-agreements", "--accept-package-agreements"
        )
    } else {
        Write-Host "[!] winget is not available. Install amass from https://github.com/owasp-amass/amass/releases"
    }
}

function Install-GoTools {
    Write-Host ""
    Write-Host "=== Go tools ==="
    if (-not (Test-Command "go")) {
        Write-Host "[!] Go is not installed or not in PATH."
        return
    }

    Add-UserPath (Get-GoBin)
    foreach ($tool in $GoTools.Keys) {
        if ($tool -eq "httpx") {
            $expectedHttpx = Get-GoToolExecutablePath "httpx"
            if (Test-Path $expectedHttpx) {
                Write-Host "[=] httpx already installed in Go bin: $expectedHttpx"
                continue
            }

            Write-Host "[*] Installing ProjectDiscovery httpx into Go bin"
            Invoke-CommandStep @("go", "install", $GoTools[$tool])
            continue
        }

        if (Test-Command $tool) {
            Write-Host "[=] $tool already exists in PATH"
            continue
        }
        Invoke-CommandStep @("go", "install", $GoTools[$tool])
    }

    Ensure-HttpxAlias
    Test-HttpxInstallation | Out-Null

    Install-Amass
}

function Install-Feroxbuster {
    Write-Host ""
    Write-Host "=== feroxbuster ==="
    if (Test-Command "feroxbuster") {
        Write-Host "[=] feroxbuster already exists in PATH"
        return
    }

    $targetDir = Join-Path $LocalToolsDir "feroxbuster"
    $zipPath = Join-Path $LocalToolsDir "feroxbuster.zip"
    $downloadUrl = "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-windows-feroxbuster.exe.zip"

    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path $LocalToolsDir | Out-Null
    }

    Invoke-CommandStep @("Invoke-WebRequest", $downloadUrl, "-OutFile", $zipPath)
    Invoke-CommandStep @("Expand-Archive", $zipPath, "-DestinationPath", $targetDir, "-Force")

    $exePath = Join-Path $targetDir "feroxbuster.exe"
    if ((-not $DryRun) -and (-not (Test-Path $exePath))) {
        $foundExe = Get-ChildItem -Path $targetDir -Recurse -Filter "feroxbuster.exe" -File |
            Select-Object -First 1
        if ($foundExe) {
            Copy-Item -Path $foundExe.FullName -Destination $exePath -Force
        }
    }

    Add-UserPath $targetDir

    if ($DryRun) {
        Write-Host "[i] Dry run: skip feroxbuster.exe version check."
    } elseif (Test-Path $exePath) {
        Invoke-CommandStep @($exePath, "-V")
    } else {
        Write-Host "[!] feroxbuster.exe was not found after extraction: $targetDir"
    }
}

function Install-OptionalTools {
    Write-Host ""
    Write-Host "=== Optional tools ==="

    Install-Feroxbuster

    if (-not (Test-Command "git")) {
        Write-Host "[!] Git is required to install dirsearch."
        return
    }

    $target = Join-Path $LocalToolsDir "dirsearch"
    if (Test-Path $target) {
        Write-Host "[=] dirsearch repository already exists: $target"
    } else {
        if (-not $DryRun) {
            New-Item -ItemType Directory -Force -Path $LocalToolsDir | Out-Null
        }
        Invoke-CommandStep @("git", "clone", "https://github.com/maurosoria/dirsearch.git", $target)
    }

    $python = Get-PythonCommand
    $requirements = Join-Path $target "requirements.txt"
    if ($python -and (Test-Path $requirements)) {
        Invoke-CommandStep @($python, "-m", "pip", "install", "-r", $requirements)
    }
}

function Test-Environment {
    Write-Host ""
    Write-Host "=== Verification ==="
    foreach ($tool in $ExpectedTools) {
        if (Test-Command $tool) {
            Write-Host "[ok] $tool"
        } elseif ($tool -eq "dirsearch" -and (Test-Path (Join-Path $LocalToolsDir "dirsearch\dirsearch.py"))) {
            Write-Host "[ok] dirsearch in tools\dirsearch"
        } else {
            Write-Host "[--] $tool not found"
        }
    }

    Test-HttpxInstallation | Out-Null
}

Write-Host "get_everything_framework Windows installer"
Write-Host "Project root: $RootDir"

if ($CheckOnly) {
    Test-Environment
    Write-Host ""
    Write-Host "Go bin: $(Get-GoBin)"
    exit 0
}

if (-not $SkipSystem) {
    Install-SystemDependencies
}

if (-not $SkipPythonDeps) {
    Install-PythonDependencies
}

if (-not $SkipGoTools) {
    Install-GoTools
}

if ($WithOptional) {
    Install-OptionalTools
} else {
    Write-Host ""
    Write-Host "=== Optional tools skipped ==="
    Write-Host "Run again with -WithOptional to install feroxbuster and clone dirsearch."
}

Test-Environment
Write-Host ""
Write-Host "[+] Done. Reopen PowerShell if newly installed commands are still not found."
