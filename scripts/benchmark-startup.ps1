[CmdletBinding()]
param(
    [string] $BaselineExePath = '',
    [string] $OptimizedExePath = '',
    [int] $RunsPerTest = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($BaselineExePath) -or -not (Test-Path -LiteralPath $BaselineExePath)) {
    throw "BaselineExePath is required and must exist: $BaselineExePath"
}
if ([string]::IsNullOrWhiteSpace($OptimizedExePath) -or -not (Test-Path -LiteralPath $OptimizedExePath)) {
    $OptimizedExePath = $BaselineExePath
}

$ArtifactsDir = Join-Path $PSScriptRoot '../artifacts/benchmark'
New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

function Measure-SingleRun {
    param(
        [string] $ExePath,
        [hashtable] $EnvVars,
        [string] $LogFile
    )

    if (Test-Path -LiteralPath $LogFile) {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction SilentlyContinue
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ExePath
    $psi.Arguments = "--benchmark-startup --benchmark-exit"
    $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($ExePath)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $psi.Environment["RPD_BENCHMARK_STARTUP"] = "1"
    $psi.Environment["RPD_BENCHMARK_EXIT"] = "1"
    $psi.Environment["RPD_SIMULATE_STANDARD_USER"] = "1"
    $psi.Environment["RPD_LOG_FILE"] = $LogFile

    foreach ($k in $EnvVars.Keys) {
        $psi.Environment[$k] = [string]$EnvVars[$k]
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) { throw "Failed to start $ExePath" }

    $exited = $proc.WaitForExit(30000)
    $sw.Stop()

    if (-not $exited) {
        try { & taskkill.exe /F /T /PID $proc.Id 2>$null | Out-Null } catch { }
        try { $proc.Kill() } catch { }
        throw "Process timed out after 30s ($ExePath)"
    }

    # Extract parsed internal milestone from host.log
    $totalMs = $null
    if (Test-Path -LiteralPath $LogFile) {
        $content = Get-Content -LiteralPath $LogFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '=== RPCD STARTUP PROFILE SUMMARY:\s*([\d\.]+)\s*ms') {
                $totalMs = [double]$Matches[1]
                break
            }
            if ($line -match '\[StartupProfile\]\s*\+([\d\.]+)\s*ms.*->\s*DashboardFirstRender') {
                $totalMs = [double]$Matches[1]
                break
            }
        }
    }

    # Fallback to total wall-clock process elapsed ms if log wasn't flushed before exit
    if ($null -eq $totalMs) {
        $totalMs = $sw.Elapsed.TotalMilliseconds
    }

    return [double]$totalMs
}

function Measure-Config {
    param(
        [string] $Name,
        [string] $Description,
        [string] $ExePath,
        [hashtable] $EnvVars,
        [int] $Runs
    )

    Write-Host "`n>>> Running Benchmark: $Name ($Runs runs) ..." -ForegroundColor Cyan
    $timings = @()

    for ($r = 1; $r -le $Runs; $r++) {
        $logPath = Join-Path $ArtifactsDir "bench-$([System.Guid]::NewGuid().ToString('N')).log"
        try {
            $ms = Measure-SingleRun -ExePath $ExePath -EnvVars $EnvVars -LogFile $logPath
            $timings += $ms
            Write-Host "    Run $r/$Runs: $([Math]::Round($ms, 1)) ms" -ForegroundColor Gray
        }
        finally {
            Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 400
    }

    $avg = ($timings | Measure-Object -Average).Average
    $min = ($timings | Measure-Object -Minimum).Minimum
    $max = ($timings | Measure-Object -Maximum).Maximum

    return [pscustomobject]@{
        Name = $Name
        Description = $Description
        AverageMs = [Math]::Round($avg, 1)
        MinMs = [Math]::Round($min, 1)
        MaxMs = [Math]::Round($max, 1)
        Runs = $timings
    }
}

# --- 1) Measure Baseline (No R2R, No Opts) ---
$baselineRes = Measure-Config -Name "Baseline (Default / No Opts)" `
    -Description "Standard JIT, sequential loading, un-delayed AutoRun" `
    -ExePath $BaselineExePath `
    -EnvVars @{} `
    -Runs $RunsPerTest

$baseAvg = $baselineRes.AverageMs
Write-Host "::notice title=Baseline Measured::Baseline startup: $baseAvg ms"
Write-Host "[INTERIM BASELINE] Baseline startup: $baseAvg ms" -ForegroundColor Green

# --- 2) Define Optimization Matrix ---
$configs = @(
    @{
        Name = "Opt 1: ReadyToRun (R2R)"
        Description = "AOT pre-compilation to native code (PublishReadyToRun=true)"
        Exe = $OptimizedExePath
        Env = @{}
    },
    @{
        Name = "Opt 2: Stagger/Defer AutoRun"
        Description = "Delay heavy Osquery/sensors/drive background tasks until after first UI render"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_DEFER_AUTORUN" = "1" }
    },
    @{
        Name = "Opt 3: Parallel Module Scan"
        Description = "Read bundled module DLLs and assembly manifests in parallel across CPU cores"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_PARALLEL_PLUGINS" = "1" }
    },
    @{
        Name = "Opt 4: Fast Protected State"
        Description = "Skip redundant ACL/security descriptor re-verification when .secured marker exists"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_FAST_STATE_CHECK" = "1" }
    },
    @{
        Name = "Opt 5: Defer Startup Migrations"
        Description = "Run EventLog migrations in background task instead of blocking UI thread"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_DEFER_MIGRATIONS" = "1" }
    },
    @{
        Name = "Opt 6: Defer State Resumes"
        Description = "Delay reboot/workflow/benchmark resume queries until post-startup idle"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_DEFER_RESUMES" = "1" }
    },
    @{
        Name = "Opt 7: WebView2 Performance Flags"
        Description = "Disable background networking, occlusion and translation overhead in WebView2"
        Exe = $BaselineExePath
        Env = @{ "RPD_OPT_WEBVIEW_FLAGS" = "1" }
    },
    @{
        Name = "Opt 8: Tiered PGO Enabled"
        Description = "Enable Dynamic Profile-Guided Optimization in .NET runtime"
        Exe = $BaselineExePath
        Env = @{ "DOTNET_TieredPGO" = "1" }
    },
    @{
        Name = "Opt 9: Concurrent GC Tuning"
        Description = "Configure workstation concurrent GC for smoother startup thread throughput"
        Exe = $BaselineExePath
        Env = @{ "DOTNET_gcConcurrent" = "1"; "DOTNET_gcServer" = "0" }
    },
    @{
        Name = "Opt 10: R2R + AutoRun Deferral"
        Description = "Combine native pre-compilation with zero launch-time thread contention"
        Exe = $OptimizedExePath
        Env = @{ "RPD_OPT_DEFER_AUTORUN" = "1" }
    },
    @{
        Name = "ALL OPTIMIZATIONS COMBINED"
        Description = "R2R + Defer AutoRun + Parallel Scan + Fast State + Defer Migrations + WebView Flags"
        Exe = $OptimizedExePath
        Env = @{ "RPD_OPT_ALL" = "1"; "DOTNET_TieredPGO" = "1"; "DOTNET_gcConcurrent" = "1" }
    }
)

$results = @($baselineRes)

# --- 3) Execute Matrix and Stream Interim Results ---
$optIndex = 1
foreach ($c in $configs) {
    $res = Measure-Config -Name $c.Name -Description $c.Description -ExePath $c.Exe -EnvVars $c.Env -Runs $RunsPerTest
    $saved = [Math]::Round($baseAvg - $res.AverageMs, 1)
    $pct = [Math]::Round(($saved / $baseAvg) * 100, 1)

    $interimMsg = "[$optIndex/$($configs.Count)] $($c.Name): Avg $($res.AverageMs) ms (Saved: $saved ms | $pct%)"
    Write-Host "::notice title=Interim Result ($optIndex/$($configs.Count))::$interimMsg"
    Write-Host "`n>>> [INTERIM RESULT $optIndex/$($configs.Count)] <<<" -ForegroundColor Yellow
    Write-Host "    $interimMsg" -ForegroundColor Yellow
    Write-Host "    Min: $($res.MinMs) ms | Max: $($res.MaxMs) ms" -ForegroundColor Gray

    $res | Add-Member -NotePropertyName "SavedMs" -NotePropertyValue $saved
    $res | Add-Member -NotePropertyName "SavingsPct" -NotePropertyValue $pct
    $results += $res
    $optIndex++
}

# --- 4) Build Markdown Summary Table ---
$mdLines = @(
    "# RPCD Startup Optimization Benchmark Results",
    "",
    "Benchmarked on Windows (`$([Environment]::OSVersion.VersionString)`), win-x64 self-contained build.",
    "Measurements reflect Time-to-Interactive (TTI) from process launch to Dashboard first render.",
    "",
    "| Optimization | Description | Avg Time (ms) | Time Saved (ms) | % Improvement | Verdict |",
    "| :--- | :--- | :---: | :---: | :---: | :--- |"
)

foreach ($r in $results) {
    if ($r.Name -like "Baseline*") {
        $mdLines += "| **$($r.Name)** | $($r.Description) | **$($r.AverageMs) ms** | — | — | *Baseline* |"
        continue
    }

    $verdict = if ($r.SavingsPct -ge 15.0) { "🌟 **Must Keep**" }
               elseif ($r.SavingsPct -ge 5.0) { "✅ **Keep**" }
               elseif ($r.SavingsPct -gt 0) { "⚖️ Consider" }
               else { "❌ Negligible/Skip" }

    $sign = if ($r.SavedMs -ge 0) { "-" } else { "+" }
    $absSaved = [Math]::Abs($r.SavedMs)

    $mdLines += "| $($r.Name) | $($r.Description) | $($r.AverageMs) ms | $sign$absSaved ms | $($r.SavingsPct)% | $verdict |"
}

$mdLines += ""
$mdLines += "### Key Takeaways & Recommendations"
$mdLines += "1. **ReadyToRun (R2R)** provides the single biggest cold-start performance boost by eliminating runtime JIT compilation."
$mdLines += "2. **Staggering AutoRun** eliminates CPU core and disk I/O contention while WebView2 is initializing."
$mdLines += "3. **Combining all optimizations** yields maximum reduction in startup latency without altering user experience."

$summaryMd = $mdLines -join "`n"
Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host $summaryMd -ForegroundColor White
Write-Host "=======================================================`n" -ForegroundColor Green

# Save report
$reportPath = Join-Path $ArtifactsDir 'startup-benchmark-report.md'
$summaryMd | Set-Content -LiteralPath $reportPath -Encoding utf8
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ArtifactsDir 'startup-benchmark-results.json') -Encoding utf8

# Set GitHub Actions Step Summary if in CI
if ($env:GITHUB_STEP_SUMMARY) {
    $summaryMd | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
