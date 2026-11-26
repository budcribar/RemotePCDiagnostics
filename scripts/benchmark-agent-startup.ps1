[CmdletBinding()]
param(
    [string] $AgentExePath = '',
    [int] $RunsPerTest = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($AgentExePath) -or -not (Test-Path -LiteralPath $AgentExePath)) {
    # Check default locations
    $candidates = @(
        (Join-Path $PSScriptRoot '../artifacts/agent/RemotePCDiagnostics.Agent-*-win-x64.exe'),
        (Join-Path $PSScriptRoot '../src/RemotePCDiagnostics.Agent/bin/Release/net11.0/win-x64/publish/RemotePCDiagnostics.Agent.exe'),
        (Join-Path $PSScriptRoot '../src/RemotePCDiagnostics.Host/bin/Release/net11.0-windows10.0.19041.0/RemotePCDiagnostics.Agent.exe'),
        (Join-Path $PSScriptRoot '../src/RemotePCDiagnostics.Agent/bin/Release/net11.0/RemotePCDiagnostics.Agent.exe')
    )
    foreach ($c in $candidates) {
        $resolved = Resolve-Path $c -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $resolved -and (Test-Path -LiteralPath $resolved.Path)) {
            $AgentExePath = $resolved.Path
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($AgentExePath) -or -not (Test-Path -LiteralPath $AgentExePath)) {
    throw "AgentExePath is required and must exist: $AgentExePath"
}

Write-Host "Benchmarking Agent: $AgentExePath" -ForegroundColor Green

function Measure-AgentCommand {
    param(
        [string] $Name,
        [string] $Arguments,
        [int] $Runs
    )

    Write-Host "`n>>> Running: $Name ('$Arguments') ($Runs runs) ..." -ForegroundColor Cyan
    $timings = @()

    for ($r = 1; $r -le $Runs; $r++) {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $AgentExePath
        $psi.Arguments = $Arguments
        $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($AgentExePath)
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) { throw "Failed to start $AgentExePath" }

        $proc.StandardOutput.ReadToEndAsync() | Out-Null
        $proc.StandardError.ReadToEndAsync() | Out-Null

        $exited = $proc.WaitForExit(10000)
        $sw.Stop()

        if (-not $exited) {
            try { $proc.Kill() } catch { }
            throw "Process timed out after 10s ($Arguments)"
        }

        $ms = $sw.Elapsed.TotalMilliseconds
        $timings += $ms
        Write-Host "    Run $r of $Runs - $([Math]::Round($ms, 1)) ms (exit code: $($proc.ExitCode))" -ForegroundColor Gray
        Start-Sleep -Milliseconds 100
    }

    $avg = ($timings | Measure-Object -Average).Average
    $min = ($timings | Measure-Object -Minimum).Minimum
    $max = ($timings | Measure-Object -Maximum).Maximum

    return [pscustomobject]@{
        Name = $Name
        Arguments = $Arguments
        AverageMs = [Math]::Round($avg, 1)
        MinMs = [Math]::Round($min, 1)
        MaxMs = [Math]::Round($max, 1)
    }
}

function Measure-HelperPipeLatency {
    param(
        [int] $Runs
    )

    Write-Host "`n>>> Running: Helper Named-Pipe Ready Latency ($Runs runs) ..." -ForegroundColor Cyan
    $timings = @()

    for ($r = 1; $r -le $Runs; $r++) {
        $pipeName = "rpd-bench-$([System.Guid]::NewGuid().ToString('N'))"
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $AgentExePath
        $psi.Arguments = "--mode=helper --parent-pid=$currentPid --pipe=$pipeName"
        $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($AgentExePath)
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.Environment["RPD_ADMIN_ALLOW_TEST_PARENT"] = "1"

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) { throw "Failed to start helper" }

        # Connect as client to measure when pipe is open and ready
        $clientPipe = [System.IO.Pipes.NamedPipeClientStream]::new(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
        $connected = $false
        try {
            $clientPipe.Connect(5000)
            $sw.Stop()
            $connected = $true
        }
        catch {
            $sw.Stop()
        }
        finally {
            try { $clientPipe.Dispose() } catch { }
            try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
            try { $proc.Dispose() } catch { }
        }

        if (-not $connected) {
            Write-Host "    Run $r of $Runs - Failed to connect to pipe" -ForegroundColor Red
            continue
        }

        $ms = $sw.Elapsed.TotalMilliseconds
        $timings += $ms
        Write-Host "    Run $r of $Runs - $([Math]::Round($ms, 1)) ms (pipe connected)" -ForegroundColor Gray
        Start-Sleep -Milliseconds 150
    }

    if ($timings.Count -gt 0) {
        $avg = ($timings | Measure-Object -Average).Average
        $min = ($timings | Measure-Object -Minimum).Minimum
        $max = ($timings | Measure-Object -Maximum).Maximum
        return [pscustomobject]@{
            Name = "Helper Pipe Ready Latency"
            Arguments = "--mode=helper"
            AverageMs = [Math]::Round($avg, 1)
            MinMs = [Math]::Round($min, 1)
            MaxMs = [Math]::Round($max, 1)
        }
    }
    return $null
}

$results = @()
$results += Measure-AgentCommand -Name "Self-Check CLI" -Arguments "--self-check" -Runs $RunsPerTest
$results += Measure-AgentCommand -Name "Status CLI" -Arguments "status" -Runs $RunsPerTest
$pipeResult = Measure-HelperPipeLatency -Runs $RunsPerTest
if ($null -ne $pipeResult) { $results += $pipeResult }

Write-Host "`n========================================================" -ForegroundColor Yellow
Write-Host "        AGENT STARTUP BENCHMARK RESULTS" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Yellow
$results | Format-Table -AutoSize
