Unicode True
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!include "MUI2.nsh"

!ifndef PAYLOAD_DIR
  !error "PAYLOAD_DIR is required"
!endif
!ifndef OUTPUT_DIR
  !error "OUTPUT_DIR is required"
!endif
!ifndef UNINSTALL_INCLUDE
  !error "UNINSTALL_INCLUDE is required"
!endif

!define PRODUCT_NAME "BC Sentinel"
!define PRODUCT_VERSION "0.13.0"
!define PRODUCT_PUBLISHER "BC TECH Studio"
!define PRODUCT_EXE "BC-Sentinel.exe"
!define PRODUCT_REGKEY "Software\BC TECH Studio\BC Sentinel"
!define UNINSTALL_REGKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel"

Name "${PRODUCT_NAME}"
OutFile "${OUTPUT_DIR}\BC-Sentinel-Setup-v0.13.0-b133.exe"
InstallDir "$LOCALAPPDATA\Programs\BC Sentinel"
InstallDirRegKey HKCU "${PRODUCT_REGKEY}" "InstallDir"
ShowInstDetails show
ShowUninstDetails show
AutoCloseWindow false

VIProductVersion "0.13.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=1033 "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=1033 "FileDescription" "BC Sentinel Setup"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright 2026 BC TECH Studio"

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Italian"

Section "BC Sentinel" SEC_MAIN
  SectionIn RO
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD_DIR}\*.*"

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "${PRODUCT_REGKEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${PRODUCT_REGKEY}" "Version" "${PRODUCT_VERSION}"

  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "DisplayIcon" "$INSTDIR\${PRODUCT_EXE}"
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_REGKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_REGKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_REGKEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\BC Sentinel"
  CreateShortcut "$SMPROGRAMS\BC Sentinel\BC Sentinel.lnk" "$INSTDIR\${PRODUCT_EXE}"
  CreateShortcut "$SMPROGRAMS\BC Sentinel\Disinstalla BC Sentinel.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section /o "Collegamento sul desktop" SEC_DESKTOP
  SetShellVarContext current
  CreateShortcut "$DESKTOP\BC Sentinel.lnk" "$INSTDIR\${PRODUCT_EXE}"
SectionEnd

LangString DESC_SEC_MAIN ${LANG_ITALIAN} "Installa BC Sentinel per l'utente corrente."
LangString DESC_SEC_DESKTOP ${LANG_ITALIAN} "Crea un collegamento opzionale sul desktop."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} $(DESC_SEC_MAIN)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} $(DESC_SEC_DESKTOP)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetShellVarContext current

  Delete "$DESKTOP\BC Sentinel.lnk"
  Delete "$SMPROGRAMS\BC Sentinel\BC Sentinel.lnk"
  Delete "$SMPROGRAMS\BC Sentinel\Disinstalla BC Sentinel.lnk"
  RMDir "$SMPROGRAMS\BC Sentinel"

  DeleteRegKey HKCU "${UNINSTALL_REGKEY}"
  DeleteRegKey HKCU "${PRODUCT_REGKEY}"

  !include "${UNINSTALL_INCLUDE}"

  ; Persistent security data intentionally lives outside $INSTDIR and is never
  ; deleted by the default uninstaller.
SectionEnd
