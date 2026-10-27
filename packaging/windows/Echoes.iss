; Echoes for Windows: the installer (Inno Setup 6.7 or newer).
;
; Installs for the current user by default, with no admin prompt (%LOCALAPPDATA%\Programs\Echoes); "Install for all
; users" (Program Files, admin) is the other choice on the first screen. An upgrade goes into the same folder in place.
; The data stays in %APPDATA%\Echoes, and an uninstall leaves it there. The release zip is the portable copy instead:
; it carries portable.txt next to Echoes.exe (Helpers/AppStorage.cs), which this installer never ships.
;
; The release workflow (.github/workflows/release.yml) builds it after "dotnet publish":
;   packaging\windows\make-wizard-images.ps1 -OutDir <images>
;   iscc /DAppVersion=<x.y.z> /DPublishDir=<publish folder> /DImageDir=<images> /O<output folder> packaging\windows\Echoes.iss
; which writes <output folder>\Echoes-Windows-x64-Setup.exe.

#if Ver < EncodeVer(6, 7, 0)
  #error Inno Setup 6.7 or newer is needed (wizard background colors)
#endif
#ifndef AppVersion
  #error Pass the version: /DAppVersion=x.y.z
#endif
#ifndef PublishDir
  #error Pass the published app: /DPublishDir=<folder with Echoes.exe>
#endif
#ifndef ImageDir
  #error Pass the wizard images: /DImageDir=<folder written by make-wizard-images.ps1>
#endif

; Setup.exe's file version takes numbers only: "1.2.0-rc.1" -> "1.2.0"
#define NumericVersion Copy(AppVersion, 1, Pos("-", AppVersion + "-") - 1)

[Setup]
; Never change AppId: it is how Setup finds an earlier install to upgrade in place.
AppId={{9E201770-C8ED-43FD-927B-46FB37698CD3}
AppName=Echoes
AppVersion={#AppVersion}
AppVerName=Echoes {#AppVersion}
AppPublisher=Echoes contributors
AppCopyright=Copyright (c) Echoes contributors
AppPublisherURL=https://github.com/SinaXhpm/Echoes
AppSupportURL=https://github.com/SinaXhpm/Echoes/issues
AppUpdatesURL=https://github.com/SinaXhpm/Echoes/releases
VersionInfoVersion={#NumericVersion}
UninstallDisplayName=Echoes
UninstallDisplayIcon={app}\Echoes.exe

PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\Echoes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

; Short: the folder (first install only), the desktop shortcut choice with the Install button (see CurPageChanged),
; then the last page with "Launch Echoes".
DisableProgramGroupPage=yes
DisableReadyPage=yes

; A running Echoes (often just its tray icon) is closed through the Restart Manager before its files are replaced.
; Echoes doesn't register for a restart, so "Launch Echoes" on the last page starts it again.
CloseApplications=yes
RestartApplications=no

; Light or dark with Windows, in the app's colors (Styles/Tokens.axaml, the v4 graphite / light grey palette): pages in
; Bg.App, the last page's logo panel in Bg.Sidebar. The images are the logo on a transparent ground, one per display
; scale (make-wizard-images.ps1). The DynamicDark lines repeat them on purpose: left out, the dark appearance would
; show Inno Setup's own images.
WizardStyle=modern dynamic windows11 hidebevels
WizardBackColor=#F5F5F7
WizardBackColorDynamicDark=#1C1C1E
WizardImageFile={#ImageDir}\wizard-*.png
WizardImageFileDynamicDark={#ImageDir}\wizard-*.png
WizardImageBackColor=#EAEAEE
WizardImageBackColorDynamicDark=#252527
WizardSmallImageFile={#ImageDir}\small-*.png
WizardSmallImageFileDynamicDark={#ImageDir}\small-*.png
WizardSmallImageBackColor=none
WizardSmallImageBackColorDynamicDark=none
; the logo in the Windows build's sizes (16 to 256 px, as the app's window and tray icon use)
SetupIconFile=..\..\Assets\echoes-windows.ico

Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
OutputBaseFilename=Echoes-Windows-x64-Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Never: debug symbols, the portable marker, or the data of a portable copy that ran from this folder
Source: "{#PublishDir}\*"; DestDir: "{app}"; Excludes: "*.pdb,portable.txt,\Echoes Data\*"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Echoes"; Filename: "{app}\Echoes.exe"
Name: "{autodesktop}\Echoes"; Filename: "{app}\Echoes.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Echoes.exe"; Description: "{cm:LaunchProgram,Echoes}"; Flags: nowait postinstall skipifsilent

[Code]
const
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupApprovedKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';
  RunValueName = 'Echoes';

{ With the Ready page left out, the page before the installation (Select Additional Tasks) says Install. }
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
    WizardForm.NextButton.Caption := SetupMessage(msgButtonInstall);
end;

{ Uninstall has no Restart Manager: a running Echoes would keep its files in use, and they would stay behind. A running
  program's file can't be opened for writing. }
function EchoesIsRunning: Boolean;
var
  Exe: String;
  Probe: TFileStream;
begin
  Result := False;
  Exe := ExpandConstant('{app}\Echoes.exe');
  try
    Probe := TFileStream.Create(Exe, fmOpenReadWrite or fmShareExclusive);
    Probe.Free;
  except
    Result := FileExists(Exe);
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
  while Result and EchoesIsRunning do
    Result := SuppressibleMsgBox('Echoes is still running. Quit it first: right-click its icon next to the clock and ' +
      'choose Quit Echoes. Then click OK.', mbError, MB_OKCANCEL, IDCANCEL) = IDOK;
end;

{ "Open Echoes when I sign in" (Helpers/AutoStart.cs) is a Run value, "<Echoes.exe>" --background, with Task Manager's
  on / off flag beside it under StartupApproved. Both go when the entry starts this copy, so no dead start-up item is
  left; an entry for another copy (a portable one) stays. }
function RunCommandProgram(const Command: String): String;
var
  P: Integer;
begin
  Result := Trim(Command);
  if Copy(Result, 1, 1) = '"' then begin
    Delete(Result, 1, 1);
    P := Pos('"', Result);
  end else
    P := Pos(' ', Result);
  if P > 0 then
    Result := Copy(Result, 1, P - 1);
end;

procedure RemoveStartupEntry;
var
  Command, Exe: String;
begin
  if not RegQueryStringValue(HKCU, RunKey, RunValueName, Command) then
    Exit;
  Exe := RunCommandProgram(Command);
  if (Exe <> '') and PathStartsWith(ExpandFileName(Exe), AddBackslash(ExpandConstant('{app}')), True) then begin
    RegDeleteValue(HKCU, RunKey, RunValueName);
    RegDeleteValue(HKCU, StartupApprovedKey, RunValueName);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveStartupEntry;
end;
