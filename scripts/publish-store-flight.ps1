<#
.SYNOPSIS
  Publishes a Microsoft Store MSIX package to Microsoft Partner Center for either
  a Package Flight (e.g. Beta / Prerelease) or a Production Store Submission.

.DESCRIPTION
  This script implements the Microsoft Store Submission API:
  1. Requests OAuth 2.0 access token from Azure AD using client credentials.
  2. Queries Partner Center application details by Store Product ID (STORE_APP_ID).
  3. If Target is 'flight', finds or creates the designated package flight, checks for
     existing submissions, and cleans up any uncommitted draft.
  4. If Target is 'submission', checks for existing production submissions and cleans up drafts.
  5. Creates a new submission (cloned from the last published submission).
  6. Compresses the MSIX package into an upload zip archive and uploads it to the Azure Blob SAS URI.
  7. Updates the submission with the new package entry (and marks older packages as PendingDelete).
  8. Commits the submission for Store certification and ingestion (unless -SkipCommit is set).
  9. Polls Partner Center submission status until ingestion begins or an error is reported.

.PARAMETER TenantId
  Azure AD Directory (tenant) ID. Falls back to $env:STORE_TENANT_ID.

.PARAMETER ClientId
  Azure AD Application (client) ID. Falls back to $env:STORE_CLIENT_ID.

.PARAMETER ClientSecret
  Azure AD Client Secret. Falls back to $env:STORE_CLIENT_SECRET.

.PARAMETER AppId
  Microsoft Store / Partner Center Product ID (e.g. 9WZDNCRD911W). Falls back to $env:STORE_APP_ID.

.PARAMETER MsixPath
  Path to the .msix file to upload.

.PARAMETER Target
  Publish target: 'flight' (package flight) or 'submission' (production store submission). Default: 'flight'.

.PARAMETER FlightName
  Friendly name of the package flight in Partner Center (e.g. 'Beta' or 'Prerelease'). Default: 'Beta'.

.PARAMETER DeletePendingDraft
  If an uncommitted draft submission is found, delete it so a clean clone can be created. Default: $true.

.PARAMETER SkipCommit
  If specified, the submission is updated with the package but not committed for certification.

.PARAMETER PollTimeoutSeconds
  Number of seconds to poll submission status after commit. Default: 300.
#>

[CmdletBinding()]
param(
    [string] $TenantId = '',
    [string] $ClientId = '',
    [string] $ClientSecret = '',
    [string] $AppId = '',
    [Parameter(Mandatory = $true)]
    [string] $MsixPath,
    [ValidateSet('flight', 'submission')]
    [string] $Target = 'flight',
    [string] $FlightName = 'Beta',
    [switch] $DeletePendingDraft = $true,
    [switch] $SkipCommit,
    [int] $PollTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string] $Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string] $Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string] $Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg {
    param([string] $Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 1. Resolve Credentials and Inputs
# ------------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($TenantId))     { $TenantId = $env:STORE_TENANT_ID }
if ([string]::IsNullOrWhiteSpace($ClientId))     { $ClientId = $env:STORE_CLIENT_ID }
if ([string]::IsNullOrWhiteSpace($ClientSecret)) { $ClientSecret = $env:STORE_CLIENT_SECRET }
if ([string]::IsNullOrWhiteSpace($AppId))        { $AppId = $env:STORE_APP_ID }

$missingCreds = @()
if ([string]::IsNullOrWhiteSpace($TenantId))     { $missingCreds += 'STORE_TENANT_ID' }
if ([string]::IsNullOrWhiteSpace($ClientId))     { $missingCreds += 'STORE_CLIENT_ID' }
if ([string]::IsNullOrWhiteSpace($ClientSecret)) { $missingCreds += 'STORE_CLIENT_SECRET' }
if ([string]::IsNullOrWhiteSpace($AppId))        { $missingCreds += 'STORE_APP_ID' }

if ($missingCreds.Count -gt 0) {
    Write-ErrMsg "Missing required Partner Center credentials: $($missingCreds -join ', ')"
    Write-ErrMsg "Please configure these secrets in your repository or pass them as parameters."
    throw "Partner Center credentials missing ($($missingCreds -join ', '))."
}

if (-not (Test-Path -LiteralPath $MsixPath)) {
    Write-ErrMsg "MSIX package file not found at: $MsixPath"
    throw "MSIX file not found: $MsixPath"
}

$MsixItem = Get-Item -LiteralPath $MsixPath
$MsixFileName = $MsixItem.Name
if (-not $MsixFileName.EndsWith('.msix', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-ErrMsg "Specified file '$MsixFileName' does not have .msix extension."
    throw "Invalid package extension for $MsixFileName"
}

$MsixSizeMb = [Math]::Round($MsixItem.Length / 1MB, 2)
$MsixHash = (Get-FileHash -LiteralPath $MsixPath -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Info "Target:           $Target"
if ($Target -eq 'flight') {
    Write-Info "Flight Name:      $FlightName"
}
Write-Info "Package:          $($MsixItem.FullName)"
Write-Info "Package Size:     $MsixSizeMb MB"
Write-Info "Package SHA256:   $MsixHash"
Write-Info "Partner Center App: $AppId"

# ------------------------------------------------------------------------------
# 2. Authenticate to Azure AD for Partner Center API
# ------------------------------------------------------------------------------
Write-Info "Requesting OAuth access token from Azure AD (tenant: $TenantId)..."
$TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$TokenBody = @{
    grant_type    = 'client_credentials'
    client_id     = $ClientId
    client_secret = $ClientSecret
    resource      = 'https://api.partner.microsoft.com'
}

$AccessToken = $null
try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method Post -Body $TokenBody -ContentType 'application/x-www-form-urlencoded'
    $AccessToken = $TokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        throw "Token response did not contain an access_token."
    }
    Write-Success "Acquired Azure AD access token (expires in $($TokenResponse.expires_in)s)."
} catch {
    Write-ErrMsg "Authentication failed! Could not obtain access token from $TokenEndpoint."
    Write-ErrMsg "Exception: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-ErrMsg "Details: $($_.ErrorDetails.Message)"
    }
    Write-ErrMsg "Verify that STORE_TENANT_ID, STORE_CLIENT_ID, and STORE_CLIENT_SECRET match your Azure AD App associated with Partner Center."
    throw "Authentication to Microsoft Store API failed."
}

$ApiBase = 'https://manage.devcenter.microsoft.com/v1.0/my/applications'
$AuthHeaders = @{
    'Authorization' = "Bearer $AccessToken"
    'User-Agent'    = 'RemotePCDiagnostics-StorePublisher/1.0'
}

# ------------------------------------------------------------------------------
# 3. Verify App in Partner Center
# ------------------------------------------------------------------------------
Write-Info "Querying Partner Center application details for Store ID: $AppId..."
$AppUrl = "$ApiBase/$AppId"
$AppData = $null
try {
    $AppData = Invoke-RestMethod -Uri $AppUrl -Method Get -Headers $AuthHeaders
    Write-Success "Found application: $($AppData.primaryName) (Package Identity: $($AppData.packageIdentityName))"
} catch {
    Write-ErrMsg "Failed to retrieve application '$AppId' from Partner Center."
    Write-ErrMsg "Exception: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-ErrMsg "Details: $($_.ErrorDetails.Message)"
    }
    throw "Application '$AppId' not found or inaccessible with current credentials."
}

# ------------------------------------------------------------------------------
# 4. Handle Submissions by Target
# ------------------------------------------------------------------------------
$SubmissionId = $null
$FileUploadUrl = $null
$SubmissionResource = $null
$FlightId = $null

if ($Target -eq 'flight') {
    Write-Info "Listing package flights for application $AppId..."
    $FlightsUrl = "$ApiBase/$AppId/listflights"
    $FlightsResp = Invoke-RestMethod -Uri $FlightsUrl -Method Get -Headers $AuthHeaders
    $FlightList = @($FlightsResp.value)

    $TargetFlight = $FlightList | Where-Object { $_.friendlyName -ieq $FlightName } | Select-Object -First 1

    if (-not $TargetFlight) {
        $AvailableNames = ($FlightList | ForEach-Object { $_.friendlyName }) -join ', '
        Write-WarnMsg "Package flight '$FlightName' not found. Existing flights: $(if ($AvailableNames) { $AvailableNames } else { '<None>' })"
        Write-Info "Attempting to create package flight '$FlightName'..."
        try {
            $CreateFlightBody = @{ friendlyName = $FlightName } | ConvertTo-Json
            $TargetFlight = Invoke-RestMethod -Uri "$ApiBase/$AppId/flights" -Method Post -Headers $AuthHeaders -ContentType 'application/json' -Body $CreateFlightBody
            Write-Success "Created new package flight '$FlightName' (ID: $($TargetFlight.flightId))."
        } catch {
            Write-ErrMsg "Could not automatically create package flight '$FlightName': $($_.Exception.Message)"
            Write-ErrMsg "Please create package flight '$FlightName' in Partner Center dashboard and assign target user flight groups."
            throw "Package flight '$FlightName' does not exist."
        }
    }

    $FlightId = $TargetFlight.flightId
    Write-Success "Selected package flight '$FlightName' (Flight ID: $FlightId)."

    # Query latest flight status to check for pending submissions
    $FlightDetailsUrl = "$ApiBase/$AppId/flights/$FlightId"
    $FlightDetails = Invoke-RestMethod -Uri $FlightDetailsUrl -Method Get -Headers $AuthHeaders

    if ($FlightDetails.pendingFlightSubmission) {
        $PendingSubId = $FlightDetails.pendingFlightSubmission.id
        Write-WarnMsg "Found existing pending flight submission: $PendingSubId"

        # Check pending submission status
        $PendingStatusUrl = "$ApiBase/$AppId/flights/$FlightId/submissions/$PendingSubId/status"
        $PendingStatusResp = Invoke-RestMethod -Uri $PendingStatusUrl -Method Get -Headers $AuthHeaders
        $PendingStatus = $PendingStatusResp.status
        Write-Info "Current status of pending submission $PendingSubId is: $PendingStatus"

        $ActiveStates = @('CommitStarted', 'PreProcessing', 'Certification', 'Publishing')
        if ($PendingStatus -in $ActiveStates) {
            Write-ErrMsg "Flight submission $PendingSubId is currently active in state '$PendingStatus'."
            Write-ErrMsg "Cannot create or overwrite a submission while an existing submission is undergoing ingestion/certification."
            Write-ErrMsg "Please wait for Partner Center to complete publishing or review the submission at https://partner.microsoft.com/dashboard."
            throw "Active submission $PendingSubId already pending in state '$PendingStatus'."
        }

        if ($DeletePendingDraft) {
            Write-Info "Deleting uncommitted draft submission $PendingSubId to start clean..."
            try {
                Invoke-RestMethod -Uri "$ApiBase/$AppId/flights/$FlightId/submissions/$PendingSubId" -Method Delete -Headers $AuthHeaders | Out-Null
                Write-Success "Deleted pending draft flight submission $PendingSubId."
            } catch {
                Write-WarnMsg "Could not delete draft submission $PendingSubId ($($_.Exception.Message)). Will attempt to update it directly."
                $SubmissionId = $PendingSubId
            }
        } else {
            Write-Info "Reusing existing uncommitted draft submission $PendingSubId."
            $SubmissionId = $PendingSubId
        }
    }

    if ([string]::IsNullOrWhiteSpace($SubmissionId)) {
        Write-Info "Creating new package flight submission for '$FlightName'..."
        $CreateSubUrl = "$ApiBase/$AppId/flights/$FlightId/submissions"
        $SubmissionResource = Invoke-RestMethod -Uri $CreateSubUrl -Method Post -Headers $AuthHeaders
        $SubmissionId = $SubmissionResource.id
        Write-Success "Created new flight submission: $SubmissionId"
    }

    # Fetch full submission details (including fileUploadUrl and existing package array)
    $SubUrl = "$ApiBase/$AppId/flights/$FlightId/submissions/$SubmissionId"
    $SubmissionResource = Invoke-RestMethod -Uri $SubUrl -Method Get -Headers $AuthHeaders
    $FileUploadUrl = $SubmissionResource.fileUploadUrl

} else {
    # Target is production 'submission'
    Write-Info "Target is production Store submission."
    if ($AppData.pendingApplicationSubmission) {
        $PendingSubId = $AppData.pendingApplicationSubmission.id
        Write-WarnMsg "Found existing pending application submission: $PendingSubId"

        $PendingStatusUrl = "$ApiBase/$AppId/submissions/$PendingSubId/status"
        $PendingStatusResp = Invoke-RestMethod -Uri $PendingStatusUrl -Method Get -Headers $AuthHeaders
        $PendingStatus = $PendingStatusResp.status
        Write-Info "Current status of pending application submission $PendingSubId is: $PendingStatus"

        $ActiveStates = @('CommitStarted', 'PreProcessing', 'Certification', 'Publishing')
        if ($PendingStatus -in $ActiveStates) {
            Write-ErrMsg "Application submission $PendingSubId is currently active in state '$PendingStatus'."
            Write-ErrMsg "Cannot create or overwrite a submission while an existing submission is undergoing ingestion/certification."
            throw "Active application submission $PendingSubId already pending in state '$PendingStatus'."
        }

        if ($DeletePendingDraft) {
            Write-Info "Deleting uncommitted draft application submission $PendingSubId to start clean..."
            try {
                Invoke-RestMethod -Uri "$ApiBase/$AppId/submissions/$PendingSubId" -Method Delete -Headers $AuthHeaders | Out-Null
                Write-Success "Deleted pending draft application submission $PendingSubId."
            } catch {
                Write-WarnMsg "Could not delete draft submission $PendingSubId ($($_.Exception.Message)). Will attempt to update it directly."
                $SubmissionId = $PendingSubId
            }
        } else {
            Write-Info "Reusing existing uncommitted draft submission $PendingSubId."
            $SubmissionId = $PendingSubId
        }
    }

    if ([string]::IsNullOrWhiteSpace($SubmissionId)) {
        Write-Info "Creating new production application submission..."
        $CreateSubUrl = "$ApiBase/$AppId/submissions"
        $SubmissionResource = Invoke-RestMethod -Uri $CreateSubUrl -Method Post -Headers $AuthHeaders
        $SubmissionId = $SubmissionResource.id
        Write-Success "Created new application submission: $SubmissionId"
    }

    $SubUrl = "$ApiBase/$AppId/submissions/$SubmissionId"
    $SubmissionResource = Invoke-RestMethod -Uri $SubUrl -Method Get -Headers $AuthHeaders
    $FileUploadUrl = $SubmissionResource.fileUploadUrl
}

if ([string]::IsNullOrWhiteSpace($FileUploadUrl)) {
    throw "Submission $SubmissionId does not contain a fileUploadUrl for package upload."
}

# ------------------------------------------------------------------------------
# 5. Compress MSIX to ZIP and Upload to SAS URI
# ------------------------------------------------------------------------------
$TempZip = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "msix-upload-$([System.Guid]::NewGuid().ToString('N')).zip")
if (Test-Path -LiteralPath $TempZip) {
    Remove-Item -LiteralPath $TempZip -Force
}

Write-Info "Archiving $MsixFileName into temporary upload zip: $TempZip..."
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $ZipArchive = [System.IO.Compression.ZipFile]::Open($TempZip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipArchive, $MsixPath, $MsixFileName, [System.IO.Compression.CompressionLevel]::Fastest) | Out-Null
    } finally {
        $ZipArchive.Dispose()
    }
} catch {
    Compress-Archive -LiteralPath $MsixPath -DestinationPath $TempZip -Force
}

$ZipSizeMb = [Math]::Round((Get-Item -LiteralPath $TempZip).Length / 1MB, 2)
Write-Success "Upload archive created ($ZipSizeMb MB)."

Write-Info "Uploading package archive to Azure Blob Storage SAS URI..."
try {
    $UploadHeaders = @{
        'x-ms-blob-type' = 'BlockBlob'
    }
    Invoke-RestMethod -Uri $FileUploadUrl -Method Put -Headers $UploadHeaders -InFile $TempZip -TimeoutSec 600
    Write-Success "Package uploaded successfully to Partner Center blob storage."
} catch {
    Write-ErrMsg "Failed to upload package archive to Azure Blob SAS URI: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-ErrMsg "Details: $($_.ErrorDetails.Message)"
    }
    throw "Azure Blob package upload failed."
} finally {
    if (Test-Path -LiteralPath $TempZip) {
        Remove-Item -LiteralPath $TempZip -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------------------
# 6. Update Submission Package Metadata
# ------------------------------------------------------------------------------
Write-Info "Updating submission $SubmissionId package metadata with '$MsixFileName'..."

$NewPackageObj = @{
    fileName              = $MsixFileName
    fileStatus            = 'PendingUpload'
    minimumDirectXVersion = 'None'
    minimumSystemRam      = 'None'
}

if ($Target -eq 'flight') {
    $Packages = @()
    if ($SubmissionResource.flightPackages) {
        foreach ($pkg in $SubmissionResource.flightPackages) {
            $pkg.fileStatus = 'PendingDelete'
            $Packages += $pkg
        }
    }
    $Packages += $NewPackageObj
    $SubmissionResource.flightPackages = $Packages

    $UpdateUrl = "$ApiBase/$AppId/flights/$FlightId/submissions/$SubmissionId"
} else {
    $Packages = @()
    if ($SubmissionResource.applicationPackages) {
        foreach ($pkg in $SubmissionResource.applicationPackages) {
            $pkg.fileStatus = 'PendingDelete'
            $Packages += $pkg
        }
    }
    $Packages += $NewPackageObj
    $SubmissionResource.applicationPackages = $Packages

    $UpdateUrl = "$ApiBase/$AppId/submissions/$SubmissionId"
}

$UpdateBodyJson = $SubmissionResource | ConvertTo-Json -Depth 12
try {
    $UpdatedResource = Invoke-RestMethod -Uri $UpdateUrl -Method Put -Headers $AuthHeaders -ContentType 'application/json' -Body $UpdateBodyJson
    Write-Success "Updated submission $SubmissionId package metadata."
} catch {
    Write-ErrMsg "Failed to update submission ${SubmissionId}: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-ErrMsg "Details: $($_.ErrorDetails.Message)"
    }
    throw "Failed to update submission with new package."
}

# ------------------------------------------------------------------------------
# 7. Commit Submission for Certification
# ------------------------------------------------------------------------------
if ($SkipCommit) {
    Write-WarnMsg "SkipCommit was specified. Submission $SubmissionId has been staged and updated with $MsixFileName, but was NOT committed."
    Write-Info "You can review and manually commit this submission in Partner Center: https://partner.microsoft.com/dashboard"
    return
}

Write-Info "Committing submission $SubmissionId for Store certification and ingestion..."
if ($Target -eq 'flight') {
    $CommitUrl = "$ApiBase/$AppId/flights/$FlightId/submissions/$SubmissionId/commit"
    $StatusCheckUrl = "$ApiBase/$AppId/flights/$FlightId/submissions/$SubmissionId/status"
} else {
    $CommitUrl = "$ApiBase/$AppId/submissions/$SubmissionId/commit"
    $StatusCheckUrl = "$ApiBase/$AppId/submissions/$SubmissionId/status"
}

try {
    Invoke-RestMethod -Uri $CommitUrl -Method Post -Headers $AuthHeaders | Out-Null
    Write-Success "Commit requested successfully. Partner Center has accepted the submission."
} catch {
    Write-ErrMsg "Commit request failed for submission ${SubmissionId}: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-ErrMsg "Details: $($_.ErrorDetails.Message)"
    }
    throw "Failed to commit submission $SubmissionId."
}

# ------------------------------------------------------------------------------
# 8. Poll Submission Status Until Ingestion Begins
# ------------------------------------------------------------------------------
Write-Info "Monitoring submission $SubmissionId commit status (timeout: ${PollTimeoutSeconds}s)..."
$StartTime = [System.Diagnostics.Stopwatch]::StartNew()
$TerminalStates = @('PreProcessing', 'Certification', 'PendingPublication', 'Publishing', 'Published', 'CommitFailed', 'PreProcessingFailed', 'CertificationFailed', 'ReleaseFailed')

$FinalStatus = 'CommitStarted'
while ($StartTime.Elapsed.TotalSeconds -lt $PollTimeoutSeconds) {
    Start-Sleep -Seconds 5
    try {
        $StatusObj = Invoke-RestMethod -Uri $StatusCheckUrl -Method Get -Headers $AuthHeaders
        $CurrentStatus = $StatusObj.status
        $FinalStatus = $CurrentStatus
        Write-Info "Elapsed: $([int]$StartTime.Elapsed.TotalSeconds)s | Status: $CurrentStatus"

        if ($CurrentStatus -eq 'CommitFailed') {
            $ErrDetails = if ($StatusObj.statusDetails -and $StatusObj.statusDetails.errors) {
                ($StatusObj.statusDetails.errors | ForEach-Object { "$($_.code): $($_.details)" }) -join '; '
            } else {
                'Unknown commit error'
            }
            Write-ErrMsg "Partner Center commit failed: $ErrDetails"
            throw "Submission commit failed with status CommitFailed ($ErrDetails)."
        }

        if ($CurrentStatus -in @('PreProcessing', 'Certification', 'PendingPublication', 'Publishing', 'Published')) {
            Write-Success "Submission $SubmissionId successfully transitioned to '$CurrentStatus'!"
            break
        }
    } catch {
        if ($_.Exception.Message -match 'CommitFailed') { throw }
        Write-WarnMsg "Error querying status ($($_.Exception.Message)), retrying in 5s..."
    }
}

$DurationSec = [int]$StartTime.Elapsed.TotalSeconds
Write-Host ""
Write-Success "=========================================================="
Write-Success "Microsoft Store Publishing Completed Successfully!"
Write-Success "  Target:        $Target $(if ($Target -eq 'flight') { "($FlightName)" } else { '' })"
Write-Success "  App ID:        $AppId"
Write-Success "  Submission ID: $SubmissionId"
Write-Success "  Package:       $MsixFileName ($MsixSizeMb MB)"
Write-Success "  SHA256:        $MsixHash"
Write-Success "  Final Status:  $FinalStatus (after ${DurationSec}s)"
Write-Success "=========================================================="
