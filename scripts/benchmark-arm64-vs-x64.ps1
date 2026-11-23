[CmdletBinding()]
param(
    [int] $Runs = 5,
    [switch] $SkipPublish,
    [switch] $IncludeNoR2R
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$HostProject = Join-Path $RepoRoot 'src/RemotePCDiagnostics.Host/RemotePCDiagnostics.Host.csproj'
$BenchRoot = Join-Path $RepoRoot 'artifacts/benchmark/arm64-vs-x64'
New-Item -ItemType Directory -Force -Path $BenchRoot | Out-Null

function Get-PeMachine {
    param([string] $Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = [System.IO.BinaryReader]::new($fs)
        $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $br.ReadInt32()
        $fs.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $machine = $br.ReadUInt16()
        switch ($machine) {
            0x8664 { return 'x64 (0x8664)' }
            0xAA64 { return 'ARM64 (0xAA64)' }
            0x014C { return 'x86 (0x014C)' }
            default { return ('0x{0:X4}' -f $machine) }
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Publish-Target {
    param(
        [string] $Rid,
        [bool] $R2R,
        [string] $OutDir
    )

    $r2rStr = if ($R2R) { 'true' } else { 'false' }
    Write-Host "`n>>> Publishing $Rid (ReadyToRun=$r2rStr) -> $OutDir ..." -ForegroundColor Cyan
    if (Test-Path -LiteralPath $OutDir) {
        Remove-Item -LiteralPath $OutDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    & dotnet publish $HostProject `
        -c Release `
        -r $Rid `
        --self-contained true `
        -p:PublishProfile=Installer `
        -p:PublishReadyToRun=$r2rStr `
        -o $OutDir

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $Rid (ReadyToRun=$r2rStr) with exit code $LASTEXITCODE"
    }

    $exe = Join-Path $OutDir 'RemotePCDiagnostics.Host.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Expected executable not found: $exe"
    }
    $arch = Get-PeMachine -Path $exe
    Write-Host "    Verified PE header: $arch" -ForegroundColor Green
    return $exe
}

function Measure-SingleRun {
    param(
        [string] $ExePath,
        [string] $LogFile
    )

    if (Test-Path -LiteralPath $LogFile) {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction SilentlyContinue
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ExePath
    $psi.Arguments = '--benchmark-startup --benchmark-exit'
    $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($ExePath)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $psi.Environment['RPD_BENCHMARK_STARTUP'] = '1'
    $psi.Environment['RPD_BENCHMARK_EXIT'] = '1'
    $psi.Environment['RPD_SIMULATE_STANDARD_USER'] = '1'
    $psi.Environment['RPD_LOG_FILE'] = $LogFile

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) { throw "Failed to start $ExePath" }

    $exited = $proc.WaitForExit(45000)
    $sw.Stop()

    if (-not $exited) {
        try { & taskkill.exe /F /T /PID $proc.Id 2>$null | Out-Null } catch { }
        try { $proc.Kill() } catch { }
        throw "Process timed out after 45s ($ExePath)"
    }

    $ttiMs = $null
    $milestones = [ordered]@{}
    if (Test-Path -LiteralPath $LogFile) {
        $lines = Get-Content -LiteralPath $LogFile -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match '\[StartupProfile\]\s*\+([\d\.]+)\s*ms\s*\(\+[\d\.]+\s*ms\)\s*->\s*(.+)$') {
                $msVal = [double]$Matches[1]
                $mName = $Matches[2].Trim()
                if (-not $milestones.Contains($mName)) {
                    $milestones[$mName] = $msVal
                }
                if ($mName -eq 'DashboardFirstRender') {
                    $ttiMs = $msVal
                }
            }
            if ($line -match '=== RPCD STARTUP PROFILE SUMMARY:\s*([\d\.]+)\s*ms') {
                $ttiMs = [double]$Matches[1]
            }
        }
    }

    $wallMs = $sw.Elapsed.TotalMilliseconds
    if ($null -eq $ttiMs) {
        $ttiMs = $wallMs
    }

    return [pscustomobject]@{
        TtiMs      = [Math]::Round($ttiMs, 1)
        WallMs     = [Math]::Round($wallMs, 1)
        ExitCode   = $proc.ExitCode
        Milestones = $milestones
    }
}

function Get-Median {
    param([double[]] $Values)
    $sorted = $Values | Sort-Object
    $n = $sorted.Count
    if ($n -eq 0) { return 0.0 }
    if ($n % 2 -eq 1) { return [double]$sorted[[int]($n / 2)] }
    return ([double]$sorted[$n / 2 - 1] + [double]$sorted[$n / 2]) / 2.0
}

function Compare-Pair {
    param(
        [string] $Label,
        [string] $X64Exe,
        [string] $Arm64Exe,
        [int] $WarmRuns
    )

    Write-Host "`n=======================================================" -ForegroundColor Magenta
    Write-Host "Benchmarking: $Label (1 cold + $WarmRuns interleaved warm runs)" -ForegroundColor Magenta
    Write-Host "  x64  : $X64Exe ($(Get-PeMachine $X64Exe))" -ForegroundColor Gray
    Write-Host "  arm64: $Arm64Exe ($(Get-PeMachine $Arm64Exe))" -ForegroundColor Gray
    Write-Host "=======================================================" -ForegroundColor Magenta

    $x64Runs = @()
    $arm64Runs = @()

    $totalIterations = $WarmRuns + 1
    for ($i = 0; $i -lt $totalIterations; $i++) {
        $tag = if ($i -eq 0) { 'Cold' } else { "Warm $i/$WarmRuns" }

        $logX64 = Join-Path $BenchRoot "x64-$i-$([guid]::NewGuid().ToString('N')).log"
        $logArm = Join-Path $BenchRoot "arm64-$i-$([guid]::NewGuid().ToString('N')).log"

        try {
            # Alternate order on odd iterations to avoid systematic order bias
            if ($i % 2 -eq 0) {
                $rX64 = Measure-SingleRun -ExePath $X64Exe -LogFile $logX64
                Start-Sleep -Milliseconds 500
                $rArm = Measure-SingleRun -ExePath $Arm64Exe -LogFile $logArm
            }
            else {
                $rArm = Measure-SingleRun -ExePath $Arm64Exe -LogFile $logArm
                Start-Sleep -Milliseconds 500
                $rX64 = Measure-SingleRun -ExePath $X64Exe -LogFile $logX64
            }

            $x64Runs += $rX64
            $arm64Runs += $rArm
            Write-Host ("  [{0,-9}] x64: TTI {1,7:F1} ms (wall {2,7:F1} ms) | arm64: TTI {3,7:F1} ms (wall {4,7:F1} ms)" -f `
                $tag, $rX64.TtiMs, $rX64.WallMs, $rArm.TtiMs, $rArm.WallMs)
        }
        finally {
            Remove-Item -LiteralPath $logX64, $logArm -Force -ErrorAction SilentlyContinue
        }

        Start-Sleep -Milliseconds 500
    }

    $x64Warm = $x64Runs | Select-Object -Skip 1
    $armWarm = $arm64Runs | Select-Object -Skip 1

    $x64WarmTti = [double[]]($x64Warm | ForEach-Object { $_.TtiMs })
    $armWarmTti = [double[]]($armWarm | ForEach-Object { $_.TtiMs })
    $x64WarmWall = [double[]]($x64Warm | ForEach-Object { $_.WallMs })
    $armWarmWall = [double[]]($armWarm | ForEach-Object { $_.WallMs })

    $x64AvgTti = [Math]::Round(($x64WarmTti | Measure-Object -Average).Average, 1)
    $armAvgTti = [Math]::Round(($armWarmTti | Measure-Object -Average).Average, 1)
    $x64MedTti = [Math]::Round((Get-Median $x64WarmTti), 1)
    $armMedTti = [Math]::Round((Get-Median $armWarmTti), 1)

    $x64AvgWall = [Math]::Round(($x64WarmWall | Measure-Object -Average).Average, 1)
    $armAvgWall = [Math]::Round(($armWarmWall | Measure-Object -Average).Average, 1)

    $ttiDiffMs = [Math]::Round($x64AvgTti - $armAvgTti, 1)
    $ttiPct = if ($x64AvgTti -gt 0) { [Math]::Round(($ttiDiffMs / $x64AvgTti) * 100, 1) } else { 0.0 }
    $wallDiffMs = [Math]::Round($x64AvgWall - $armAvgWall, 1)
    $wallPct = if ($x64AvgWall -gt 0) { [Math]::Round(($wallDiffMs / $x64AvgWall) * 100, 1) } else { 0.0 }

    # Per-milestone warm averages
    $allMilestoneNames = @()
    foreach ($r in ($x64Warm + $armWarm)) {
        foreach ($k in $r.Milestones.Keys) {
            if ($allMilestoneNames -notcontains $k) { $allMilestoneNames += $k }
        }
    }
    $milestoneRows = @()
    foreach ($m in $allMilestoneNames) {
        $xv = @($x64Warm | Where-Object { $_.Milestones.Contains($m) } | ForEach-Object { [double]$_.Milestones[$m] })
        $av = @($armWarm | Where-Object { $_.Milestones.Contains($m) } | ForEach-Object { [double]$_.Milestones[$m] })
        if ($xv.Count -gt 0 -and $av.Count -gt 0) {
            $xa = [Math]::Round(($xv | Measure-Object -Average).Average, 1)
            $aa = [Math]::Round(($av | Measure-Object -Average).Average, 1)
            $milestoneRows += [pscustomobject]@{
                Milestone = $m
                X64Ms     = $xa
                Arm64Ms   = $aa
                SavedMs   = [Math]::Round($xa - $aa, 1)
            }
        }
    }

    return [pscustomobject]@{
        Label         = $Label
        ColdX64Tti    = $x64Runs[0].TtiMs
        ColdArm64Tti  = $arm64Runs[0].TtiMs
        ColdX64Wall   = $x64Runs[0].WallMs
        ColdArm64Wall = $arm64Runs[0].WallMs
        WarmX64AvgTti = $x64AvgTti
        WarmArmAvgTti = $armAvgTti
        WarmX64MedTti = $x64MedTti
        WarmArmMedTti = $armMedTti
        TtiSavedMs    = $ttiDiffMs
        TtiFasterPct  = $ttiPct
        WarmX64AvgWall = $x64AvgWall
        WarmArmAvgWall = $armAvgWall
        WallSavedMs   = $wallDiffMs
        WallFasterPct = $wallPct
        Milestones    = $milestoneRows
    }
}

$pairs = @(
    @{ Label = 'ReadyToRun (Installer default)'; R2R = $true; Suffix = 'r2r' }
)
if ($IncludeNoR2R) {
    $pairs += @{ Label = 'Standard JIT (No ReadyToRun)'; R2R = $false; Suffix = 'jit' }
}

$summaries = @()
foreach ($p in $pairs) {
    $x64Dir = Join-Path $BenchRoot "stage-win-x64-$($p.Suffix)"
    $armDir = Join-Path $BenchRoot "stage-win-arm64-$($p.Suffix)"

    if ($SkipPublish) {
        $x64Exe = Join-Path $x64Dir 'RemotePCDiagnostics.Host.exe'
        $armExe = Join-Path $armDir 'RemotePCDiagnostics.Host.exe'
        if (-not (Test-Path -LiteralPath $x64Exe) -or -not (Test-Path -LiteralPath $armExe)) {
            throw "SkipPublish specified, but staged executables not found in $x64Dir / $armDir"
        }
    }
    else {
        $x64Exe = Publish-Target -Rid 'win-x64' -R2R $p.R2R -OutDir $x64Dir
        $armExe = Publish-Target -Rid 'win-arm64' -R2R $p.R2R -OutDir $armDir
    }

    $summaries += Compare-Pair -Label $p.Label -X64Exe $x64Exe -Arm64Exe $armExe -WarmRuns $Runs
}

# Build Markdown report
$md = @(
    '# RPCD Startup Benchmark: win-arm64 vs win-x64'
    ''
    "- **OS:** $([Environment]::OSVersion.VersionString) ($($env:PROCESSOR_ARCHITECTURE))"
    "- **Runs:** 1 cold + $Runs interleaved warm runs per target"
    ''
    '| Build | Metric | win-x64 | win-arm64 | Saved | % Faster |'
    '| :--- | :--- | :---: | :---: | :---: | :---: |'
)

foreach ($s in $summaries) {
    $coldDiff = [Math]::Round($s.ColdX64Tti - $s.ColdArm64Tti, 1)
    $coldPct = if ($s.ColdX64Tti -gt 0) { [Math]::Round(($coldDiff / $s.ColdX64Tti) * 100, 1) } else { 0.0 }
    $md += "| $($s.Label) | Cold TTI | $($s.ColdX64Tti) ms | $($s.ColdArm64Tti) ms | $coldDiff ms | $coldPct% |"
    $md += "| $($s.Label) | **Warm Avg TTI** | **$($s.WarmX64AvgTti) ms** | **$($s.WarmArmAvgTti) ms** | **$($s.TtiSavedMs) ms** | **$($s.TtiFasterPct)%** |"
    $md += "| $($s.Label) | Warm Median TTI | $($s.WarmX64MedTti) ms | $($s.WarmArmMedTti) ms | $([Math]::Round($s.WarmX64MedTti - $s.WarmArmMedTti, 1)) ms | — |"
    $md += "| $($s.Label) | Warm Avg Wall-Clock | $($s.WarmX64AvgWall) ms | $($s.WarmArmAvgWall) ms | $($s.WallSavedMs) ms | $($s.WallFasterPct)% |"
}

foreach ($s in $summaries) {
    if ($s.Milestones.Count -gt 0) {
        $md += ''
        $md += "### Milestone Breakdown — $($s.Label) (Warm Avg)"
        $md += ''
        $md += '| Milestone | win-x64 | win-arm64 | Saved |'
        $md += '| :--- | :---: | :---: | :---: |'
        foreach ($m in $s.Milestones) {
            $md += "| $($m.Milestone) | $($m.X64Ms) ms | $($m.Arm64Ms) ms | $($m.SavedMs) ms |"
        }
    }
}

$reportText = $md -join "`n"
$reportPath = Join-Path $BenchRoot 'arm64-vs-x64-report.md'
$jsonPath = Join-Path $BenchRoot 'arm64-vs-x64-results.json'
$reportText | Set-Content -LiteralPath $reportPath -Encoding utf8
$summaries | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding utf8

Write-Host "`n$reportText`n" -ForegroundColor White
Write-Host "Saved report: $reportPath" -ForegroundColor Green

if ($env:GITHUB_STEP_SUMMARY) {
    $reportText | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
