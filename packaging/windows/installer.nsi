; The Nex - one-click Windows installer (NSIS 3, Unicode).
;
; Build (CI does this):
;   makensis /DVERSION=0.4.1 /DSRCDIR=<folder> /DOUTFILE=<path>\TheNexSetup.exe installer.nsi
; where <folder> holds the-nex.exe, the-nex-gui.exe, thenex_model.onnx and icon.ico.
;
; Double-click -> one administrator prompt -> files go to %ProgramData%\TheNex (the folder the
; service reads its model and settings from), the service is registered and started, the tray
; icon starts for the signed-in user, and Start menu / desktop shortcuts plus an Apps & Features
; uninstaller are created. Silent: TheNexSetup.exe /S

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.4.1"
!endif
!ifndef SRCDIR
  !error "Pass /DSRCDIR=<folder with the-nex.exe, the-nex-gui.exe, thenex_model.onnx and icon.ico>"
!endif
!ifndef OUTFILE
  !define OUTFILE "TheNexSetup.exe"
!endif

!define APPNAME "The Nex"
!define SERVICE "TheNex"
!define UNINSTALLER "Uninstall The Nex.exe"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\TheNex"
!define RUNKEY "Software\Microsoft\Windows\CurrentVersion\Run"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

Name "${APPNAME}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\TheNex" ; replaced by %ProgramData%\TheNex in .onInit
ShowInstDetails show
ShowUninstDetails show
BrandingText "${APPNAME} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "${APPNAME} installer"
VIAddVersionKey "LegalCopyright" "${APPNAME}"

!define MUI_ICON "${SRCDIR}\icon.ico"
!define MUI_UNICON "${SRCDIR}\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_TITLE "The Nex is installed and protecting this PC"
!define MUI_FINISHPAGE_TEXT "The background service is running and the tray icon has started.$\r$\n$\r$\nTip: switch on Dry run in Settings first if you want to see what The Nex would block before it acts."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open The Nex"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchDashboard

; One click: no welcome, licence or folder pages - straight to installing, then Finish.
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "The Nex needs 64-bit Windows 10 or 11." /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  ; Must match the service's data folder (%ProgramData%\TheNex).
  ReadEnvStr $0 "ProgramData"
  ${If} $0 == ""
    StrCpy $0 "$WINDIR\..\ProgramData"
  ${EndIf}
  StrCpy $INSTDIR "$0\TheNex"
FunctionEnd

; Explorer starts the target as the signed-in user, without this installer's admin rights.
Function LaunchDashboard
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\the-nex-gui.exe"'
FunctionEnd

!macro StopTheNex
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${SERVICE}'
  Pop $0
  Sleep 1500
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /F /T /IM the-nex.exe'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /F /T /IM the-nex-gui.exe'
  Pop $0
  Sleep 500
!macroend

Section "The Nex" SecMain
  SetShellVarContext all

  DetailPrint "Stopping any running copy of The Nex..."
  !insertmacro StopTheNex

  ; A user may have pre-created %ProgramData%\TheNex: take ownership for Administrators and drop
  ; its ACLs before anything runs as SYSTEM from here (failures are ignored if it is absent).
  ; Whose it was has to be asked first: a folder that was neither ours nor an administrator's may
  ; hold made-up settings, which the engine then moves aside (--fresh-data). Not knowing counts as
  ; not ours, except over an installed copy.
  StrCpy $2 ""
  ReadRegStr $1 HKLM "${UNINSTKEY}" "UninstallString"
  ReadRegStr $3 HKLM "Software\TheNex" "FreshData"
  ${If} $3 != ""
    ; An earlier try found that out and did not finish: the folder is an administrator's by now.
    StrCpy $2 " --fresh-data"
  ${ElseIf} $1 == ""
  ${AndIf} ${FileExists} "$INSTDIR"
    nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "if ([int][IO.File]::GetAttributes('$INSTDIR') -band 1024) { exit 8 }; if ([IO.Directory]::GetAccessControl('$INSTDIR').GetOwner([Security.Principal.SecurityIdentifier]).Value -in 'S-1-5-32-544','S-1-5-18') { exit 0 }; exit 7"`
    Pop $0
    ${If} $0 == 8
      MessageBox MB_ICONSTOP "$INSTDIR leads to another folder, so nothing was installed. Remove it and try again." /SD IDOK
      SetErrorLevel 2
      Abort
    ${ElseIf} $0 != 0
      StrCpy $2 " --fresh-data"
      WriteRegStr HKLM "Software\TheNex" "FreshData" "1"
    ${EndIf}
  ${EndIf}
  CreateDirectory "$INSTDIR"
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T /C'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /reset /T /C'
  Pop $0

  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "${SRCDIR}\the-nex.exe"
  File "${SRCDIR}\the-nex-gui.exe"
  File "${SRCDIR}\thenex_model.onnx"
  ; Known-malware list: present only in builds made with one (the service refuses any other).
  Delete "$INSTDIR\known_bad.bin"
  File /nonfatal "${SRCDIR}\known_bad.bin"
  File "${SRCDIR}\icon.ico"
  WriteUninstaller "$INSTDIR\${UNINSTALLER}"

  DetailPrint "Registering the background service..."
  nsExec::ExecToLog '"$INSTDIR\the-nex.exe" --install$2'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Registering The Nex service failed (exit code $0). See the details list for the reason." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
  DeleteRegValue HKLM "Software\TheNex" "FreshData"
  DeleteRegKey /ifempty HKLM "Software\TheNex"

  DetailPrint "Starting the background service..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" start ${SERVICE}'
  Pop $0

  CreateDirectory "$SMPROGRAMS\The Nex"
  CreateShortcut "$SMPROGRAMS\The Nex\The Nex.lnk" "$INSTDIR\the-nex-gui.exe" "" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\The Nex\Uninstall The Nex.lnk" "$INSTDIR\${UNINSTALLER}"
  CreateShortcut "$DESKTOP\The Nex.lnk" "$INSTDIR\the-nex-gui.exe" "" "$INSTDIR\icon.ico"
  CreateShortcut "$INSTDIR\The Nex Tray.lnk" "$INSTDIR\the-nex.exe" "--tray" "$INSTDIR\icon.ico"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\${UNINSTALLER}"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER}" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1

  ; Tray icon for the person installing (later sign-ins start it from the Run key).
  ${IfNot} ${Silent}
    Exec '"$WINDIR\explorer.exe" "$INSTDIR\The Nex Tray.lnk"'
  ${EndIf}
SectionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Uninstall"
  SetShellVarContext all

  DetailPrint "Removing the background service..."
  nsExec::ExecToLog '"$INSTDIR\the-nex.exe" --uninstall'
  Pop $0
  !insertmacro StopTheNex
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete ${SERVICE}'
  Pop $0
  DeleteRegValue HKLM "${RUNKEY}" "TheNexNotifier"
  DeleteRegValue HKCU "${RUNKEY}" "TheNexTray"

  Delete "$INSTDIR\the-nex.exe"
  Delete "$INSTDIR\the-nex-gui.exe"
  Delete "$INSTDIR\thenex_model.onnx"
  Delete "$INSTDIR\known_bad.bin"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\The Nex Tray.lnk"
  Delete "$INSTDIR\${UNINSTALLER}"
  Delete "$SMPROGRAMS\The Nex\The Nex.lnk"
  Delete "$SMPROGRAMS\The Nex\Uninstall The Nex.lnk"
  RMDir "$SMPROGRAMS\The Nex"
  Delete "$DESKTOP\The Nex.lnk"
  DeleteRegKey HKLM "${UNINSTKEY}"

  ; Removed only if empty: logs, settings and quarantined files are kept on purpose.
  RMDir "$INSTDIR"
  IfFileExists "$INSTDIR\*.*" 0 +2
    DetailPrint "Kept $INSTDIR (logs, settings and quarantined files)."
SectionEnd
