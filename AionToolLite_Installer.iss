; Inno Setup Script for AionToolLite (Compatible with Inno Setup 6 and 7)
#ifndef AppVer
  #define AppVer "1.0.0"
#endif

[Setup]
AppId={{7E8A1C3F-9B42-4D1E-8C6A-2F5B9E1D4A7C}
AppName=AionToolLite
AppVersion={#AppVer}
AppVerName=AionToolLite {#AppVer}
AppPublisher=Yoqaizo
AppPublisherURL=https://github.com/Yoqaizo/AionToolLite
AppSupportURL=https://github.com/Yoqaizo/AionToolLite/issues
AppUpdatesURL=https://github.com/Yoqaizo/AionToolLite/releases
DefaultDirName={autopf}\AionToolLite
DefaultGroupName=AionToolLite
LicenseFile=LICENSE
OutputDir=.\Installer
OutputBaseFilename=AionToolLite_Setup_v{#AppVer}
SetupIconFile=AionToolLite\AionToolp.ico
UninstallDisplayIcon={app}\AionToolLite.exe
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
#if VER >= 0x06030000
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
#endif
CloseApplications=force
RestartApplications=no

[Files]
Source: "AionToolLite\bin\Release\net8.0-windows\win-x64\publish\AionToolLite.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "AionToolLite\bin\Release\net8.0-windows\win-x64\publish\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "AionToolLite\AionToolp.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AionToolLite"; Filename: "{app}\AionToolLite.exe"; WorkingDir: "{app}"; IconFilename: "{app}\AionToolp.ico"
Name: "{commondesktop}\AionToolLite"; Filename: "{app}\AionToolLite.exe"; WorkingDir: "{app}"; IconFilename: "{app}\AionToolp.ico"

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN AionToolLite_AutoStart /F"; Flags: runhidden; RunOnceId: "RemoveAionToolLiteAutoStart"

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\AionToolLite"
Type: filesandordirs; Name: "{commonappdata}\AionToolLite"

[Run]
; runascurrentuser + shellexec prevents CreateProcess error 740 on elevated exe and works cleanly in silent auto-updates
Filename: "{app}\AionToolLite.exe"; WorkingDir: "{app}"; Description: "Launch AionToolLite"; Flags: nowait postinstall runascurrentuser shellexec

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { Ensure any running or Tray-hidden AionToolLite instance is closed before replacing files and launching the new version }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM AionToolLite.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
