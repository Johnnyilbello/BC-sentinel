param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$ArgumentList,
    [Parameter(Mandatory=$true)][string]$WorkingDirectory
)
$ErrorActionPreference = "Stop"

# This launcher is intentionally used only by the ADMIN acceptance harness.
# It obtains the filtered/medium-integrity token from Explorer in the current
# interactive session, duplicates it as a primary token, and starts the helper
# with that token. The child acceptance script independently verifies that it is
# NOT administrator before it can report PASS.

$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class BCStandardUserLauncher
{
    private const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    private const UInt32 TOKEN_DUPLICATE = 0x0002;
    private const UInt32 TOKEN_QUERY = 0x0008;
    private const UInt32 MAXIMUM_ALLOWED = 0x02000000;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;
    private const UInt32 LOGON_WITH_PROFILE = 0x00000001;
    private const UInt32 CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        UInt32 dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        UInt32 dwLogonFlags,
        string lpApplicationName,
        StringBuilder lpCommandLine,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static UInt32 StartFromProcessToken(UInt32 sourcePid, string application, string arguments, string cwd)
    {
        IntPtr process = IntPtr.Zero;
        IntPtr token = IntPtr.Zero;
        IntPtr primary = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
            if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess(explorer) failed");

            if (!OpenProcessToken(process, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken(explorer) failed");

            if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out primary))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = @"winsta0\default";
            StringBuilder command = new StringBuilder("\"" + application + "\" " + arguments);

            if (!CreateProcessWithTokenW(
                primary,
                LOGON_WITH_PROFILE,
                application,
                command,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                cwd,
                ref si,
                out pi))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithTokenW failed");
            }

            return pi.dwProcessId;
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (process != IntPtr.Zero) CloseHandle(process);
        }
    }
}
'@

if (-not ("BCStandardUserLauncher" -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp
}

$currentSession = (Get-Process -Id $PID).SessionId
$explorer = Get-Process explorer -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -eq $currentSession } |
    Sort-Object StartTime |
    Select-Object -First 1
if (-not $explorer) {
    throw "Explorer non trovato nella sessione interattiva corrente; impossibile creare un vero processo standard-user."
}

$childPid = [BCStandardUserLauncher]::StartFromProcessToken(
    [uint32]$explorer.Id,
    $FilePath,
    $ArgumentList,
    $WorkingDirectory
)

Write-Output $childPid
