; Inno Setup 6 installer script for Remote PC Diagnostics (win-x64).
; Build via: pwsh -NoProfile -File installer/Build-Installer.ps1

#ifndef AppVersion
  #define AppVersion "1.2.0"
#endif
#ifndef AppNumericVersion
  #define AppNumericVersion "1.2.0.0"
#endif
#ifndef RepoRoot
  #define RepoRoot ".."
#endif
#ifndef PublishDir
  #define PublishDir "..\artifacts\installer-stage"
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts\installer"
#endif

#define AppName "Remote PC Diagnostics"
#define AppPublisher "Remote PC Diagnostics"
#define AppExeName "RemotePCDiagnostics.Host.exe"
; How the shortcuts (Start menu, desktop) and the "launch now" box at the end of setup start the app: a remote session on
; the public relay, shared with the remote user, with a voice call. Running the exe with no arguments is still Local mode.
#define RemoteParameters "-u=https://remoteblazorwebview.com:34544 --voice"
#define AppMutexName "Global\RemotePCDiagnostics.Host"
#define WebView2ClientId "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WebView2BootstrapUrl "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
#define WorkflowResumeTaskName "Remote PC Diagnostics - continue service workflow"
#define RebootRunOnceValueName "RemotePCDiagnosticsResume"

[Setup]
AppId={{8F6D4A2E-5C91-4B73-9E18-3A7C2D9F41B0}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
VersionInfoVersion={#AppNumericVersion}
VersionInfoProductName={#AppName}
VersionInfoProductTextVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\RemotePCDiagnostics
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
#if VER >= EncodeVer(6,3,0,0)
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
#endif
MinVersion=10.0.19041
PrivilegesRequired=admin
AppMutex={#AppMutexName}
CloseApplications=yes
RestartApplications=no
LicenseFile={#RepoRoot}\LICENSE
SetupIconFile={#RepoRoot}\src\RemotePCDiagnostics.Host\Assets\diagnostics.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename=RemotePCDiagnostics-Setup-{#AppVersion}-win-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Dirs]
; Plugin and declarative-check drop folders discovered by ModuleLoader and JsonCheck under %ProgramFiles%\RemotePCDiagnostics.
Name: "{app}\modules"
Name: "{app}\checks"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; WorkingDir: "{app}"; Comment: "Start a remote session (shared screen and voice)"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; WorkingDir: "{app}"; Comment: "Start a remote session (shared screen and voice)"; Tasks: desktopicon

[Run]
; shellexec is required because RemotePCDiagnostics.Host.exe declares requireAdministrator in its manifest.
Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Remove the post-reboot workflow continuation scheduled task if an interrupted workflow left one registered.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#WorkflowResumeTaskName}"" /F"; Flags: runhidden; RunOnceId: "DeleteWorkflowResumeTask"

[Code]
var
  DownloadPage: TDownloadWizardPage;
  WebView2BootstrapperPath: String;

function CmdLineParamExists(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), Value) = 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function HasValidWebView2Version(const RootKey: Integer): Boolean;
var
  Version: String;
begin
  Result :=
    RegQueryStringValue(RootKey, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{#WebView2ClientId}', 'pv', Version) and
    (Version <> '') and
    (Version <> '0.0.0.0');
end;

function IsWebView2Installed(): Boolean;
begin
  Result :=
    HasValidWebView2Version(HKLM32) or
    HasValidWebView2Version(HKLM64) or
    HasValidWebView2Version(HKCU);
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if Progress = ProgressMax then
    Log(Format('Downloaded WebView2 bootstrapper to {tmp}: %s', [FileName]));
  Result := True;
end;

procedure InitializeWizard();
begin
  WebView2BootstrapperPath := '';
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  BundledBootstrapper: String;
begin
  Result := True;
  if (CurPageID = wpReady) and (not CmdLineParamExists('/SKIPWEBVIEW2')) and (not IsWebView2Installed()) then
  begin
    BundledBootstrapper := ExpandConstant('{src}\MicrosoftEdgeWebview2Setup.exe');
    if FileExists(BundledBootstrapper) then
    begin
      WebView2BootstrapperPath := BundledBootstrapper;
      Log('Using local WebView2 bootstrapper: ' + WebView2BootstrapperPath);
    end
    else if not WizardSilent() then
    begin
      DownloadPage.Clear;
      DownloadPage.Add('{#WebView2BootstrapUrl}', 'MicrosoftEdgeWebview2Setup.exe', '');
      DownloadPage.Show;
      try
        try
          DownloadPage.Download;
          WebView2BootstrapperPath := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
        except
          if DownloadPage.AbortedByUser then
            Log('WebView2 download cancelled by user.')
          else
            SuppressibleMsgBox(
              'Microsoft Edge WebView2 Runtime is required, and downloading the bootstrapper failed:' + #13#10#13#10 +
              AddPeriod(GetExceptionMessage) + #13#10#13#10 +
              'Connect to the internet and try again, or place MicrosoftEdgeWebview2Setup.exe next to this Setup executable.',
              mbCriticalError, MB_OK, IDOK);
          Result := False;
        end;
      finally
        DownloadPage.Hide;
      end;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  BundledBootstrapper: String;
  ResultCode: Integer;
begin
  Result := '';
  if CmdLineParamExists('/SKIPWEBVIEW2') or IsWebView2Installed() then
    Exit;

  if WebView2BootstrapperPath = '' then
  begin
    BundledBootstrapper := ExpandConstant('{src}\MicrosoftEdgeWebview2Setup.exe');
    if FileExists(BundledBootstrapper) then
      WebView2BootstrapperPath := BundledBootstrapper
    else
    begin
      try
        DownloadTemporaryFile('{#WebView2BootstrapUrl}', 'MicrosoftEdgeWebview2Setup.exe', '', nil);
        WebView2BootstrapperPath := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
      except
        Result := 'Microsoft Edge WebView2 Runtime is required, and downloading its installer failed: ' + AddPeriod(GetExceptionMessage);
        Exit;
      end;
    end;
  end;

  if not FileExists(WebView2BootstrapperPath) then
  begin
    Result := 'Microsoft Edge WebView2 Runtime is not installed and its bootstrapper could not be found.';
    Exit;
  end;

  WizardForm.StatusLabel.Caption := 'Installing Microsoft Edge WebView2 Runtime...';
  Log('Installing WebView2 Evergreen Runtime via: ' + WebView2BootstrapperPath);
  if not Exec(WebView2BootstrapperPath, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := Format('Failed to launch Microsoft Edge WebView2 Runtime installer (%s).', [SysErrorMessage(ResultCode)]);
    Exit;
  end;

  if (ResultCode <> 0) and (not IsWebView2Installed()) then
  begin
    Result := Format('Microsoft Edge WebView2 Runtime installation failed with exit code %d.', [ResultCode]);
    Exit;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProgramDataDir: String;
  LocalAppDataDir: String;
  HasStateDirs: Boolean;
  ShouldClean: Boolean;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\RunOnce', '{#RebootRunOnceValueName}') then
      Log('Removed pending RunOnce resume entry {#RebootRunOnceValueName}.');

    ProgramDataDir := ExpandConstant('{commonappdata}\RemotePCDiagnostics');
    LocalAppDataDir := ExpandConstant('{localappdata}\RemotePCDiagnostics');
    HasStateDirs := DirExists(ProgramDataDir) or DirExists(LocalAppDataDir);
    if not HasStateDirs then
      Exit;

    ShouldClean := CmdLineParamExists('/CLEANSTATE');
    if (not ShouldClean) and (not UninstallSilent()) then
    begin
      ShouldClean := MsgBox(
        'Do you also want to remove saved diagnostic logs, benchmark history, preferences, and undo state?' + #13#10#13#10 +
        '  - ' + ProgramDataDir + #13#10 +
        '  - ' + LocalAppDataDir + #13#10#13#10 +
        'Choose No if you plan to reinstall or upgrade and want to keep your history and undo records.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
    end;

    if ShouldClean then
    begin
      if DirExists(ProgramDataDir) then
      begin
        Log('Removing ProgramData folder: ' + ProgramDataDir);
        DelTree(ProgramDataDir, True, True, True);
      end;
      if DirExists(LocalAppDataDir) then
      begin
        Log('Removing LocalAppData folder: ' + LocalAppDataDir);
        DelTree(LocalAppDataDir, True, True, True);
      end;
    end;
  end;
end;
