Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ProcessNative {

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount,
        int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags,
        IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr ShellExecute(IntPtr hwnd, string lpOperation, string lpFile,
        string lpParameters, string lpDirectory, int nShowCmd);

    public const uint TOKEN_ALL_ACCESS             = 0xF01FF;
    public const uint SE_PRIVILEGE_ENABLED         = 0x00000002;
    public const uint TH32CS_SNAPPROCESS           = 0x00000002;
    public const uint PROCESS_CREATE_PROCESS       = 0x0080;
    public const uint PROCESS_DUP_HANDLE           = 0x0040;
    public const uint PROCESS_SET_INFORMATION      = 0x0200;
    public const uint CREATE_NEW_CONSOLE           = 0x00000010;
    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const uint SC_MANAGER_CONNECT           = 0x0001;
    public const uint SERVICE_QUERY_STATUS         = 0x0004;
    public const uint SERVICE_START                = 0x0010;
    public const uint SERVICE_STOP                 = 0x0020;
    public const uint SERVICE_CONTROL_STOP         = 0x00000001;
    public const uint SERVICE_RUNNING              = 0x00000004;
    public const int  SW_NORMAL                    = 1;
    public static readonly IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = new IntPtr(0x00020000);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int  HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32 {
        public uint   dwSize;
        public uint   cntUsage;
        public uint   th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint   th32ModuleID;
        public uint   cntThreads;
        public uint   th32ParentProcessID;
        public int    pcPriClassBase;
        public uint   dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int    cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars;
        public int    dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow;
        public short  cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int    dwProcessId;
        public int    dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }
}
"@

# --- Helper functions ---

function Enable-SeDebugPrivilege {
    $hProcess = [ProcessNative]::GetCurrentProcess()
    $hToken   = [IntPtr]::Zero

    if (-not [ProcessNative]::OpenProcessToken($hProcess, [ProcessNative]::TOKEN_ALL_ACCESS, [ref]$hToken)) {
        throw "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $luid = New-Object ProcessNative+LUID
    if (-not [ProcessNative]::LookupPrivilegeValue([NullString]::Value, "SeDebugPrivilege", [ref]$luid)) {
        throw "LookupPrivilegeValue failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $tp = New-Object ProcessNative+TOKEN_PRIVILEGES
    $tp.PrivilegeCount = 1
    $tp.Privileges = @(New-Object ProcessNative+LUID_AND_ATTRIBUTES)
    $tp.Privileges[0].Luid       = $luid
    $tp.Privileges[0].Attributes = [ProcessNative]::SE_PRIVILEGE_ENABLED

    if (-not [ProcessNative]::AdjustTokenPrivileges($hToken, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
        throw "AdjustTokenPrivileges failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    [ProcessNative]::CloseHandle($hToken) | Out-Null
}

function Get-TrustedInstallerPid {
    $hSnap = [ProcessNative]::CreateToolhelp32Snapshot([ProcessNative]::TH32CS_SNAPPROCESS, 0)
    if ($hSnap -eq [IntPtr]::new(-1)) {
        throw "CreateToolhelp32Snapshot failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    try {
        $entry = New-Object ProcessNative+PROCESSENTRY32
        $entry.dwSize = [Runtime.InteropServices.Marshal]::SizeOf($entry)

        if (-not [ProcessNative]::Process32First($hSnap, [ref]$entry)) {
            throw "Process32First failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        do {
            if ($entry.szExeFile -ieq "TrustedInstaller.exe") {
                return $entry.th32ProcessID
            }
        } while ([ProcessNative]::Process32Next($hSnap, [ref]$entry))

        throw "Cannot find TrustedInstaller.exe in running process list"
    }
    finally {
        [ProcessNative]::CloseHandle($hSnap) | Out-Null
    }
}

function Test-IsAdmin {
    try {
        $f = [System.IO.File]::Open("\\.\PHYSICALDRIVE0", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $f.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-Elevate {
    $exe  = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $args = $MyInvocation.UnboundArguments -join " "
    $cwd  = (Get-Location).Path

    $result = [ProcessNative]::ShellExecute([IntPtr]::Zero, "runas", $exe, $args, $cwd, [ProcessNative]::SW_NORMAL)
    if ($result.ToInt64() -le 32) {
        throw "ShellExecute runas failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    exit 0
}

# --- Main ---

function Run-AsTrustedInstaller {
    param(
        [string]$Path = "cmd.exe",
        [string[]]$Arguments = @("/c", "start", "cmd.exe")
    )

    if (-not (Test-IsAdmin)) {
        Invoke-Elevate
    }

    Enable-SeDebugPrivilege
    Write-Host "[+] SeDebugPrivilege enabled"

    # Open SCM
    $hSCM = [ProcessNative]::OpenSCManager([NullString]::Value, [NullString]::Value, [ProcessNative]::SC_MANAGER_CONNECT)
    if ($hSCM -eq [IntPtr]::Zero) {
        throw "OpenSCManager failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    # Open TrustedInstaller service
    $svcAccess = [ProcessNative]::SERVICE_QUERY_STATUS -bor [ProcessNative]::SERVICE_START -bor [ProcessNative]::SERVICE_STOP
    $hService  = [ProcessNative]::OpenService($hSCM, "TrustedInstaller", $svcAccess)
    if ($hService -eq [IntPtr]::Zero) {
        throw "OpenService failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    # Query / start service
    $svcStatus = New-Object ProcessNative+SERVICE_STATUS
    $needStop  = $false

    if (-not [ProcessNative]::QueryServiceStatus($hService, [ref]$svcStatus)) {
        throw "QueryServiceStatus failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    if ($svcStatus.dwCurrentState -ne [ProcessNative]::SERVICE_RUNNING) {
        Write-Host "[*] Starting TrustedInstaller service..."
        if (-not [ProcessNative]::StartService($hService, 0, [IntPtr]::Zero)) {
            throw "StartService failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        Start-Sleep -Milliseconds 500
        $needStop = $true
        Write-Host "[+] TrustedInstaller service started"
    }

    # Get TI PID and open process
    $tiPid = Get-TrustedInstallerPid
    Write-Host "[+] TrustedInstaller PID: $tiPid"

    $procAccess = [ProcessNative]::PROCESS_CREATE_PROCESS -bor
                  [ProcessNative]::PROCESS_DUP_HANDLE -bor
                  [ProcessNative]::PROCESS_SET_INFORMATION

    $hTI = [ProcessNative]::OpenProcess($procAccess, $true, $tiPid)
    if ($hTI -eq [IntPtr]::Zero) {
        throw "OpenProcess on TI failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    # PPID spoofing
    $attrList   = [IntPtr]::Zero
    $hParentMem = [IntPtr]::Zero

    try {
        $lpSize = [IntPtr]::Zero
        [ProcessNative]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$lpSize) | Out-Null
        $attrList = [Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)

        if (-not [ProcessNative]::InitializeProcThreadAttributeList($attrList, 1, 0, [ref]$lpSize)) {
            throw "InitializeProcThreadAttributeList failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        $hParentMem = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($hParentMem, $hTI)

        if (-not [ProcessNative]::UpdateProcThreadAttribute(
            $attrList, 0,
            [ProcessNative]::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            $hParentMem, [IntPtr]::new([IntPtr]::Size),
            [IntPtr]::Zero, [IntPtr]::Zero))
        {
            throw "UpdateProcThreadAttribute failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        $startupInfo    = New-Object ProcessNative+STARTUPINFO
        $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf([Type][ProcessNative+STARTUPINFOEX])

        $si                 = New-Object ProcessNative+STARTUPINFOEX
        $si.StartupInfo     = $startupInfo
        $si.lpAttributeList = $attrList

        $pi = New-Object ProcessNative+PROCESS_INFORMATION

        $cmdLine = "$Path $($Arguments -join ' ')"
        $flags   = [ProcessNative]::CREATE_NEW_CONSOLE -bor [ProcessNative]::EXTENDED_STARTUPINFO_PRESENT

        if (-not [ProcessNative]::CreateProcess(
            [NullString]::Value, $cmdLine,
            [IntPtr]::Zero, [IntPtr]::Zero,
            $false, $flags,
            [IntPtr]::Zero, [NullString]::Value,
            [ref]$si, [ref]$pi))
        {
            throw "CreateProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        Write-Host "[+] Started process with PID $($pi.dwProcessId)"

        [ProcessNative]::CloseHandle($pi.hProcess) | Out-Null
        [ProcessNative]::CloseHandle($pi.hThread)  | Out-Null
    }
    finally {
        if ($attrList -ne [IntPtr]::Zero) {
            [ProcessNative]::DeleteProcThreadAttributeList($attrList)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($attrList)
        }
        if ($hParentMem -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($hParentMem)
        }
        [ProcessNative]::CloseHandle($hTI) | Out-Null

        if ($needStop) {
            $stopStatus = New-Object ProcessNative+SERVICE_STATUS
            [ProcessNative]::ControlService($hService, [ProcessNative]::SERVICE_CONTROL_STOP, [ref]$stopStatus) | Out-Null
            Write-Host "[*] TrustedInstaller service stopped"
        }

        [ProcessNative]::CloseServiceHandle($hService) | Out-Null
        [ProcessNative]::CloseServiceHandle($hSCM)     | Out-Null
    }
}

Run-AsTrustedInstaller -Path "cmd.exe" -Arguments @("/c", "start", "cmd.exe")