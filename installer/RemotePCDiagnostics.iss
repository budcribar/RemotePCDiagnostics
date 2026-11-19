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

#ifndef OutputBaseName
  #define OutputBaseName "RemotePCDiagnostics-Setup-" + AppVersion + "-win-x64"
#endif
#ifndef RemoteServerUrl
  #define RemoteServerUrl "https://remoteblazorwebview.com:34544"
#endif
#ifndef ShopGroup
  #define ShopGroup ""
#endif
#ifndef AgentExePath
  #define AgentExePath ""
#endif
#ifndef AgentServerUrl
  #define AgentServerUrl "https://server.remoteblazorwebview.com:34544"
#endif
#ifndef AgentEnrollmentKey
  #define AgentEnrollmentKey ""
#endif
#ifndef AgentConsent
  #define AgentConsent "unattended"
#endif

#define AppName "Remote PC Diagnostics"
#define AppPublisher "Remote PC Diagnostics"
#define AppExeName "RemotePCDiagnostics.Host.exe"
; How the shortcuts (Start menu, desktop) and the "launch now" box at the end of setup start the app: a remote session on
; the public relay, shared with the remote user, with a voice call. Running the exe with no arguments is still Local mode.
#if ShopGroup != ""
  #define RemoteParameters "-u=" + RemoteServerUrl + " -g=" + ShopGroup + " --voice"
#else
  #define RemoteParameters "-u=" + RemoteServerUrl + " --voice"
#endif
; /AGENTSERVER=<url> on the Setup command line replaces the relay the bundled agent enrols with. CI installs the bundle with a
; loopback address, so its smoke test never registers the build runner with the public relay.
#if AgentExePath != ""
  #define AgentInstallParams "install --server={param:AGENTSERVER|" + AgentServerUrl + "} --consent=" + AgentConsent + " --lifetime=persistent"
  #if AgentEnrollmentKey != ""
    #define AgentInstallParams AgentInstallParams + " --key=" + AgentEnrollmentKey
  #endif
  #if ShopGroup != ""
    #define AgentInstallParams AgentInstallParams + " --group=" + ShopGroup
  #endif
#endif
#define AppMutexName "Global\RemotePCDiagnostics.Host"
#define WebView2ClientId "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WebView2BootstrapUrl "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
#define WorkflowResumeTaskName "Remote PC Diagnostics - continue service workflow"
#define RebootRunOnceValueName "RemotePCDiagnosticsResume"
#define RebootResumeTaskName "Remote PC Diagnostics - continue after restart"

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
SetupIconFile={#RepoRoot}\src\RemotePCDiagnostics.Host\Assets\diagnostics.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=no
WizardSizePercent=100,100
WizardImageFile={#RepoRoot}\installer\WizardImage.bmp
WizardSmallImageFile={#RepoRoot}\installer\WizardSmallImage.bmp
DisableWelcomePage=yes
DisableDirPage=yes
DisableReadyPage=yes
DisableFinishedPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[LangOptions]
DialogFontName=Segoe UI
DialogFontSize=9
TitleFontName=Segoe UI
TitleFontSize=11
WelcomeFontName=Segoe UI
WelcomeFontSize=12
CopyrightFontName=Segoe UI
CopyrightFontSize=8

[Dirs]
; Plugin and declarative-check drop folders discovered by ModuleLoader and JsonCheck under %ProgramFiles%\RemotePCDiagnostics.
Name: "{app}\modules"
Name: "{app}\checks"
; Shared sessions folder under %ProgramData% so standard user Host instances can publish active-session.json
Name: "{commonappdata}\RemotePCDiagnostics\sessions"; Permissions: users-modify

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#if AgentExePath != ""
Source: "{#AgentExePath}"; DestDir: "{tmp}"; DestName: "RemotePCDiagnostics.Agent.exe"; Flags: ignoreversion
#endif

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; WorkingDir: "{app}"; Comment: "Start a remote session (shared screen and voice)"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; WorkingDir: "{app}"; Comment: "Start a remote session (shared screen and voice)"

[Run]
#if AgentExePath != ""
; Stage Agent.exe in {tmp} and invoke 'install' so any running RemotePCDiagnosticsAgent service is stopped cleanly before updating Program Files.
Filename: "{tmp}\RemotePCDiagnostics.Agent.exe"; Parameters: "{#AgentInstallParams}"; StatusMsg: "Installing and starting Remote PC Diagnostics Agent service..."; Flags: runhidden waituntilterminated
#endif
; In-app updates (AppUpdateService / the agent's AgentSelfUpdater) pass /AGENTMSI=<verified Agent MSI> when the persistent
; agent service is installed: Setup upgrades it here, because the app and its elevated helper are closed by now and cannot.
Filename: "{sys}\msiexec.exe"; Parameters: "/i ""{param:AGENTMSI}"" /qn /norestart"; StatusMsg: "Updating Remote PC Diagnostics Agent service..."; Check: HasSetupParam('AGENTMSI'); Flags: runhidden waituntilterminated
; In-app updates also pass /RELAUNCHARGS=<the app's restart command line> (same relay, session id and group), so the app comes
; back into the remote session it was in. The entry below it skips silent installs, so without this nothing restarts the app.
Filename: "{app}\{#AppExeName}"; Parameters: "{param:RELAUNCHARGS}"; WorkingDir: "{app}"; Check: ShouldRelaunchAfterUpdate; Flags: nowait shellexec runasoriginaluser
; shellexec + runasoriginaluser launches RemotePCDiagnostics.Host.exe (asInvoker) as the interactive desktop user at the end of setup.
Filename: "{app}\{#AppExeName}"; Parameters: "{#RemoteParameters}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; WorkingDir: "{app}"; Flags: nowait skipifsilent shellexec runasoriginaluser

[UninstallRun]
; Remove the post-reboot workflow continuation scheduled task if an interrupted workflow left one registered.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#WorkflowResumeTaskName}"" /F"; Flags: runhidden; RunOnceId: "DeleteWorkflowResumeTask"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#RebootResumeTaskName}"" /F"; Flags: runhidden; RunOnceId: "DeleteRebootResumeTask"

[Code]
var
  DownloadPage: TDownloadWizardPage;
  WebView2BootstrapperPath: String;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { Direct Progress: skip all wizard pages except wpInstalling }
  Result := (PageID <> wpInstalling);
end;

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

{ True when Setup was started with /<Name>=<value> and a value. }
function HasSetupParam(const Name: String): Boolean;
begin
  Result := ExpandConstant('{param:' + Name + '|}') <> '';
end;

{ Restart the app after a silent in-app update. An interactive install already starts it with the entry after this one. }
function ShouldRelaunchAfterUpdate(): Boolean;
begin
  Result := WizardSilent() and HasSetupParam('RELAUNCHARGS');
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
  WizardForm.Font.Name := 'Segoe UI';
  WizardForm.StatusLabel.Font.Name := 'Segoe UI';
  WizardForm.FilenameLabel.Font.Name := 'Segoe UI';
  WizardForm.PageNameLabel.Font.Name := 'Segoe UI';
  WizardForm.PageDescriptionLabel.Font.Name := 'Segoe UI';
  WizardForm.CancelButton.Font.Name := 'Segoe UI';
  WizardForm.Bevel.Visible := False;

  WebView2BootstrapperPath := '';
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
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

procedure RemoveInstalledAgent();
var
  AgentDir, AgentExe, ProgramDataDir: String;
  I, ResultCode: Integer;
begin
  { Setup can run the agent's own uninstall. MSIX cannot (no custom uninstall action); the service removes itself
    once it has seen this install and later finds it gone. install-agent / Install-Computer.cmd only call
    "Agent.exe install ... --lifetime=persistent", so this same uninstall command is what removes them. }
  AgentDir := ExpandConstant('{autopf}\RemotePCDiagnosticsAgent');
  AgentExe := ExpandConstant('{autopf}\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe');
  if FileExists(AgentExe) then
  begin
    Log('Removing Remote PC Diagnostics Agent: ' + AgentExe);
    if Exec(AgentExe, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Log('Agent uninstall finished with exit code ' + IntToStr(ResultCode) + '.')
    else
      Log('Could not start the agent uninstaller. Removing the service and enrollment key directly.');
  end
  else
    Log('Agent executable not found at ' + AgentExe + '. Removing any leftover service and enrollment key.');

  { Idempotent if uninstall already did this. Covers a missing exe or an uninstall that did not start. }
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop RemotePCDiagnosticsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete RemotePCDiagnosticsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "RemotePCDiagnostics Agent" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "RemotePCDiagnosticsAgent" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnosticsAgent');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnosticsAgent');

  for I := 1 to 10 do
  begin
    if not FileExists(AgentExe) then
      Break;
    if DeleteFile(AgentExe) then
      Break;
    Sleep(200);
  end;
  if DirExists(AgentDir) then
    DelTree(AgentDir, True, True, True);

  ProgramDataDir := ExpandConstant('{commonappdata}\RemotePCDiagnostics');
  if FileExists(ProgramDataDir + '\agent.json') then
    DeleteFile(ProgramDataDir + '\agent.json');
  if FileExists(ProgramDataDir + '\agent-status.json') then
    DeleteFile(ProgramDataDir + '\agent-status.json');
  if FileExists(ProgramDataDir + '\agent-host.json') then
    DeleteFile(ProgramDataDir + '\agent-host.json');
  if FileExists(ProgramDataDir + '\active-session.json') then
    DeleteFile(ProgramDataDir + '\active-session.json');
  if DirExists(ProgramDataDir + '\sessions') then
    DelTree(ProgramDataDir + '\sessions', True, True, True);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProgramDataDir: String;
  LocalAppDataDir: String;
  HasStateDirs: Boolean;
  ShouldClean: Boolean;
begin
  if CurUninstallStep = usUninstall then
    RemoveInstalledAgent();

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
