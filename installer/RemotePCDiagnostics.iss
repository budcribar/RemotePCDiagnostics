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
; Release builds keep lzma2/ultra64. CI passes lzma2/fast for builds nobody downloads (pull requests, TestShop-only runs).
#ifndef Compression
  #define Compression "lzma2/ultra64"
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
; The agent service has its own mutex (Global\RemotePCDiagnostics.Agent). It is not listed as AppMutex.
; Silent Setup checks AppMutex before it can close anything, and /SUPPRESSMSGBOXES answers Cancel, so a mutex
; the agent still holds would make a remote update exit 1. PrepareToInstall stops the old agent instead.
; Agent.exe install waits until that mutex is free, sets the service to Automatic, turns failure restart back
; on, and starts it. DeinitializeSetup does the same again: it is Setup itself, not the agent process that
; launched Setup. That agent is stopped by the upgrade and must not be what starts the new service.
; Startup is Automatic. A delayed start would leave the PC off the relay for about two minutes.
#define AgentMutexName "Global\RemotePCDiagnostics.Agent"
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
Compression={#Compression}
SolidCompression=yes
; Compress in 64 MB blocks on 4 threads (the GitHub runners have 4 cores). Single-threaded ultra64 took about 2.5 minutes
; per installer; the blocks cost a little compression ratio. ISCC is a 32-bit process and 4 ultra64 threads need more
; memory than it can address ("Out of memory"), so compression runs in the separate 64-bit ISLZMA process.
LZMANumBlockThreads=4
LZMABlockSize=65536
LZMAUseSeparateProcess=yes
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
; Stage Agent.exe in {tmp} and invoke 'install'. PrepareToInstall has already stopped the old agent service,
; its legacy service names, and the Run keys and scheduled tasks that would start a second copy.
; install waits until the agent mutex is free, sets Automatic and failure restart, and only then starts the service.
; These entries are not skipifsilent: a remote update is silent. DeinitializeSetup starts the service again
; if this entry does not, including when the agent that launched Setup has already been stopped.
; A remote update passes /PRESERVEAGENT so install keeps the enrollment key, consent, and lifetime already on the PC.
Filename: "{tmp}\RemotePCDiagnostics.Agent.exe"; Parameters: "{#AgentInstallParams}"; StatusMsg: "Installing and starting Remote PC Diagnostics Agent service..."; Flags: runhidden waituntilterminated; Check: not PreserveAgentSettings
Filename: "{tmp}\RemotePCDiagnostics.Agent.exe"; Parameters: "install"; StatusMsg: "Updating Remote PC Diagnostics Agent service..."; Flags: runhidden waituntilterminated; Check: PreserveAgentSettings
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

{ Remote update: install the agent service again without --consent, --lifetime, --key, or --server, so the existing ones stay. }
function PreserveAgentSettings(): Boolean;
begin
  Result := CmdLineParamExists('/PRESERVEAGENT');
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

{ Stop every service name this product has used, and remove startup entries that launch a second copy.
  Does not delete the current service and does not taskkill: Setup may be a child of the agent that started
  this update, and sc delete while that process is still alive leaves the old version running with no service
  record. Agent.exe install deletes legacy names only after the process and the agent mutex are gone.
  Failure restart is cleared first so the stop does not launch a second copy that exits 0 and stays stopped.
  The start type stays Automatic. DeinitializeSetup turns failure restart back on and starts the service. }
function ServiceQueryText(const Name: String): String;
var
  OutputPath, Text: String;
  Code: Integer;
begin
  Result := '';
  OutputPath := ExpandConstant('{tmp}\rpcd-sc-query.txt');
  if Exec(ExpandConstant('{sys}\cmd.exe'), '/C sc query "' + Name + '" > "' + OutputPath + '" 2>&1', '', SW_HIDE, ewWaitUntilTerminated, Code) then
    if LoadStringFromFile(OutputPath, Text) then
      Result := Text;
end;

function AgentServiceIsInstalled(): Boolean;
var
  Text: String;
begin
  Text := ServiceQueryText('RemotePCDiagnosticsAgent');
  Result := (Pos('STATE', Text) > 0) and (Pos('1060', Text) = 0);
end;

procedure ScLog(const Args: String);
var
  Code: Integer;
begin
  if Exec(ExpandConstant('{sys}\sc.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Log('sc ' + Args + ' exited ' + IntToStr(Code) + '.')
  else
    Log('Could not start sc.exe for: ' + Args);
end;

procedure ClearAgentFailureRestart(const Name: String);
begin
  ScLog('failureflag "' + Name + '" 0');
  ScLog('failure "' + Name + '" reset= 0 actions= ""');
end;

procedure StopOneAgentService(const Name: String);
begin
  Log('Stopping agent service ''' + Name + ''' before the new agent starts.');
  ClearAgentFailureRestart(Name);
  ScLog('stop "' + Name + '"');
end;

procedure EnsureAgentServiceAutomaticAndRunning();
var
  Code, Try: Integer;
  Text: String;
begin
  if not AgentServiceIsInstalled() then
  begin
    Log('RemotePCDiagnosticsAgent is not installed. Setup is not starting it.');
    Exit;
  end;
  { Automatic. A delayed start would leave the PC off the relay after boot. }
  ScLog('config RemotePCDiagnosticsAgent start= auto');
  ScLog('failureflag RemotePCDiagnosticsAgent 0');
  ScLog('failure RemotePCDiagnosticsAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000');
  { A start that finds the previous process still holding the agent mutex exits 0 and stays stopped.
    Exit 0 does not trip failure restart. Try again once that process is gone. }
  for Try := 1 to 8 do
  begin
    if not Exec(ExpandConstant('{sys}\sc.exe'), 'start RemotePCDiagnosticsAgent', '', SW_HIDE, ewWaitUntilTerminated, Code) then
    begin
      Log('Could not start sc.exe to start RemotePCDiagnosticsAgent.');
      Exit;
    end;
    if (Code <> 0) and (Code <> 1056) then
      Log('sc start RemotePCDiagnosticsAgent exited ' + IntToStr(Code) + '.');
    Sleep(2000);
    Text := ServiceQueryText('RemotePCDiagnosticsAgent');
    if Pos('RUNNING', Text) > 0 then
    begin
      Log('RemotePCDiagnosticsAgent is set to Automatic and is running.');
      Exit;
    end;
    Log('RemotePCDiagnosticsAgent was not running yet.');
  end;
  Log('RemotePCDiagnosticsAgent did not stay running.');
end;

procedure DeinitializeSetup();
begin
  EnsureAgentServiceAutomaticAndRunning();
end;

procedure RemoveAgentStartupEntries();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "RemotePCDiagnostics Agent" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "RemotePCDiagnosticsAgent" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "Remote PC Diagnostics Agent" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnosticsAgent');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnostics Agent');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Remote PC Diagnostics Agent');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnosticsAgent');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'RemotePCDiagnostics Agent');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Remote PC Diagnostics Agent');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'RemotePCDiagnosticsAgent');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'RemotePCDiagnosticsAgent');
end;

procedure StopPreviousAgents();
begin
  Log('Stopping any running Remote PC Diagnostics Agent before installing {#AgentMutexName}.');
  StopOneAgentService('RemotePCDiagnosticsAgent');
  StopOneAgentService('RemotePCDiagnostics.Agent');
  StopOneAgentService('Remote PC Diagnostics Agent');
  StopOneAgentService('RemotePCDiagnostics Agent');
  RemoveAgentStartupEntries();
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
end;

{ Silent Setup checks AppMutex inside its own initialization, before CloseApplications.
  /SUPPRESSMSGBOXES answers that OK/Cancel prompt with Cancel, and Setup then exits 1
  (failed to initialize) without copying a file. A remote update runs while the technician
  session still has this Host open, so close it before that check. Not /T: when the elevated
  helper started Setup, Setup is a descendant of the Host, and /T would end Setup too. }
function InitializeSetup(): Boolean;
var
  Code, Tries: Integer;
begin
  Result := True;
  if not WizardSilent() then
    Exit;
  if not CheckForMutexes('{#AppMutexName}') then
    Exit;

  Log('Remote PC Diagnostics is still running. Silent Setup would exit 1 while that mutex is held, before it can close the app. Closing it.');
  if not Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName}', '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Log('Could not start taskkill. Setup will keep failing while the app is running.')
  else
    Log('taskkill exited with code ' + IntToStr(Code) + '.');

  for Tries := 1 to 50 do
  begin
    if not CheckForMutexes('{#AppMutexName}') then
    begin
      Log('Remote PC Diagnostics has exited. Setup can continue.');
      Exit;
    end;
    Sleep(200);
  end;
  Log('Remote PC Diagnostics is still running after taskkill. Setup cannot initialize while the application mutex is held.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  BundledBootstrapper: String;
  ResultCode: Integer;
begin
  Result := '';
  { Before files are copied and before [Run] starts the new agent. Almost every PC has WebView2, and the
    check below returns immediately, so this has to run first. }
  StopPreviousAgents();
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
  StopPreviousAgents();
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "Remote PC Diagnostics Setup" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop "RemotePCDiagnostics.Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete "RemotePCDiagnostics.Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop "Remote PC Diagnostics Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete "Remote PC Diagnostics Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop "RemotePCDiagnostics Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete "RemotePCDiagnostics Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  RemoveAgentStartupEntries();

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
  if FileExists(ProgramDataDir + '\agent-instance.txt') then
    DeleteFile(ProgramDataDir + '\agent-instance.txt');
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
