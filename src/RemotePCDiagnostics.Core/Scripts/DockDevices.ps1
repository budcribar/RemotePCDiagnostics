$ErrorActionPreference = 'Stop'
$present = @(Get-PnpDevice -PresentOnly -Class Monitor,USB,Net,AudioEndpoint)
$usb = @(Get-CimInstance Win32_USBHub | ForEach-Object PNPDeviceID)
$ethernet = @(Get-NetAdapter -Physical | Where-Object { $_.NdisPhysicalMedium -eq 14 -or $_.MediaType -eq '802.3' } | ForEach-Object PnPDeviceID)
$connections = $null
try {
    $connections = @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorConnectionParams)
} catch { }
$devices = @(foreach ($device in $present) {
    $kind = switch ($device.Class) {
        'Monitor' { if ($device.InstanceId -like 'DISPLAY\*') { 'Display' } }
        'USB' { if ($device.InstanceId -in $usb) { 'USB hub' } }
        'Net' { if ($device.InstanceId -in $ethernet) { 'Ethernet' } }
        'AudioEndpoint' { 'Audio endpoint' }
    }
    if (-not $kind) { continue }
    $container = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction SilentlyContinue
    $monitor = if ($kind -eq 'Display') {
        $connections | Where-Object { ($_.InstanceName -replace '_\d+$', '') -eq $device.InstanceId } | Select-Object -First 1
    }
    [pscustomobject]@{
        Id = $device.InstanceId
        Kind = $kind
        Name = if ($device.FriendlyName) { $device.FriendlyName } else { $kind }
        Status = $device.Status
        Container = if ($container.Data) { [string]$container.Data } else { $null }
        Active = if ($monitor) { $monitor.Active } else { $null }
        Connection = if ($monitor) {
            switch ($monitor.VideoOutputTechnology) {
                { $_ -in 6,11,13,2147483648 } { 'Built-in display' }
                0 { 'VGA' }
                4 { 'DVI' }
                5 { 'HDMI' }
                10 { 'External DisplayPort' }
                15 { 'Miracast' }
                16 { 'Indirect wired display' }
                default { $null }
            }
        } else { $null }
    }
})
ConvertTo-Json -InputObject $devices -Compress
