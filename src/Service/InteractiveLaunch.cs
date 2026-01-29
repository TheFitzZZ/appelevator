using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class InteractiveLaunch
{
    public static bool IsProcessRunningInActiveSession(string processName)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF)
        {
            return false;
        }

        try
        {
            return Process.GetProcessesByName(processName)
                .Any(process =>
                {
                    try
                    {
                        return process.SessionId == sessionId;
                    }
                    catch
                    {
                        return false;
                    }
                });
        }
        catch
        {
            return false;
        }
    }

    public static void LaunchInActiveSession(string commandLine)
    {
        EnablePrivilege("SeTcbPrivilege");
        EnablePrivilege("SeAssignPrimaryTokenPrivilege");
        EnablePrivilege("SeIncreaseQuotaPrivilege");

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF)
        {
            throw new InvalidOperationException("No active session found.");
        }

        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                out var processToken))
        {
            throw new InvalidOperationException($"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
        }

        try
        {
            if (!DuplicateTokenEx(processToken, TokenAccessLevels.MaximumAllowed, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out var primaryToken))
            {
                throw new InvalidOperationException($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                if (!SetTokenInformation(primaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(uint)))
                {
                    throw new InvalidOperationException($"SetTokenInformation failed: {Marshal.GetLastWin32Error()}");
                }

                if (!CreateEnvironmentBlock(out var environment, primaryToken, false))
                {
                    throw new InvalidOperationException($"CreateEnvironmentBlock failed: {Marshal.GetLastWin32Error()}");
                }

                try
                {
                    var startupInfo = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFO>(),
                        lpDesktop = "winsta0\\default"
                    };

                    var procInfo = new PROCESS_INFORMATION();
                    const uint creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

                    if (!CreateProcessAsUser(primaryToken, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                            creationFlags, environment, null, ref startupInfo, out procInfo))
                    {
                        throw new InvalidOperationException($"CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");
                    }

                    CloseHandle(procInfo.hThread);
                    CloseHandle(procInfo.hProcess);
                }
                finally
                {
                    DestroyEnvironmentBlock(environment);
                }
            }
            finally
            {
                CloseHandle(primaryToken);
            }
        }
        finally
        {
            CloseHandle(processToken);
        }
    }

    private static void EnablePrivilege(string privilegeName)
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tokenHandle))
        {
            throw new InvalidOperationException($"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
        }

        try
        {
            if (!LookupPrivilegeValue(null, privilegeName, out var luid))
            {
                throw new InvalidOperationException($"LookupPrivilegeValue failed: {Marshal.GetLastWin32Error()}");
            }

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                }
            };

            if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw new InvalidOperationException($"AdjustTokenPrivileges failed: {Marshal.GetLastWin32Error()}");
            }
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        TokenAccessLevels desiredAccess,
        IntPtr tokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE tokenType,
        out IntPtr newToken);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        ref uint tokenInformation,
        int tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
