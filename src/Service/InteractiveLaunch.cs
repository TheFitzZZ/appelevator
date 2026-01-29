using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

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

    public static void LaunchInActiveSession(string commandLine, bool createConsole = false)
    {
        TryLaunchWithLogonUserInActiveSession(commandLine, createConsole);
    }

    private static IntPtr GetPrimaryTokenForActiveSession(uint sessionId)
    {
        if (WTSQueryUserToken(sessionId, out var userToken))
        {
            if (!DuplicateTokenEx(userToken, TokenAccessLevels.MaximumAllowed, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out var primaryToken))
            {
                throw new InvalidOperationException($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");
            }

            CloseHandle(userToken);
            return primaryToken;
        }

        var explorer = Process.GetProcessesByName("explorer")
            .FirstOrDefault(proc =>
            {
                try
                {
                    return proc.SessionId == sessionId;
                }
                catch
                {
                    return false;
                }
            });

        if (explorer == null)
        {
            throw new InvalidOperationException("No explorer.exe found in the active session.");
        }

        if (!OpenProcessToken(explorer.Handle, TOKEN_DUPLICATE | TOKEN_QUERY, out var explorerToken))
        {
            throw new InvalidOperationException($"OpenProcessToken(explorer) failed: {Marshal.GetLastWin32Error()}");
        }

        if (!DuplicateTokenEx(explorerToken, TokenAccessLevels.MaximumAllowed, IntPtr.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out var explorerPrimary))
        {
            throw new InvalidOperationException($"DuplicateTokenEx(explorer) failed: {Marshal.GetLastWin32Error()}");
        }

        CloseHandle(explorerToken);
        return explorerPrimary;
    }

    private static bool TryLaunchAsServiceAccountInActiveSession(string commandLine, bool createConsole)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF)
        {
            return false;
        }

        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            out var processToken))
        {
            return false;
        }

        try
        {
            var desiredAccess = (TokenAccessLevels)(TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
            if (!DuplicateTokenEx(processToken, desiredAccess, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out var primaryToken))
            {
                return false;
            }

            try
            {
                if (!SetTokenInformation(primaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(uint)))
                {
                    return false;
                }

                if (!CreateEnvironmentBlock(out var environment, primaryToken, false))
                {
                    return false;
                }

                try
                {
                    var profile = new PROFILEINFO
                    {
                        dwSize = Marshal.SizeOf<PROFILEINFO>(),
                        lpUserName = GetUserNameFromToken(primaryToken)
                    };

                    LoadUserProfile(primaryToken, ref profile);

                    var startupInfo = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFO>(),
                        lpDesktop = "winsta0\\default",
                        dwFlags = STARTF_USESHOWWINDOW,
                        wShowWindow = SW_SHOW
                    };

                    var procInfo = new PROCESS_INFORMATION();
                    var creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB |
                        (createConsole ? CREATE_NEW_CONSOLE : 0);

                    if (!CreateProcessAsUser(primaryToken, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                            creationFlags, environment, null, ref startupInfo, out procInfo))
                    {
                        return false;
                    }

                    CloseHandle(procInfo.hThread);
                    CloseHandle(procInfo.hProcess);

                    if (profile.hProfile != IntPtr.Zero)
                    {
                        UnloadUserProfile(primaryToken, profile.hProfile);
                    }

                    return true;
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

    private static bool TryLaunchViaTaskScheduler(string commandLine)
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                return false;
            }

            var credentials = GetServiceCredentials();
            var user = credentials.userName;
            var password = credentials.password;

            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(user))
            {
                return false;
            }

            var (path, args) = SplitCommandLine(commandLine);

            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType == null)
            {
                return false;
            }

            dynamic service = Activator.CreateInstance(schedulerType)!;
            service.Connect();

            dynamic rootFolder = service.GetFolder("\\");
            dynamic taskDefinition = service.NewTask(0);

            taskDefinition.RegistrationInfo.Description = "AppElevator interactive launch";
            taskDefinition.Settings.Enabled = true;
            taskDefinition.Settings.Hidden = false;

            taskDefinition.Principal.UserId = user;
            taskDefinition.Principal.LogonType = TASK_LOGON_PASSWORD;
            taskDefinition.Principal.RunLevel = TASK_RUNLEVEL_HIGHEST;

            dynamic action = taskDefinition.Actions.Create(TASK_ACTION_EXEC);
            action.Path = path;
            action.Arguments = args;

            dynamic registeredTask = rootFolder.RegisterTaskDefinition(
                "AppElevator-Launch",
                taskDefinition,
                TASK_CREATE_OR_UPDATE,
                user,
                password,
                TASK_LOGON_PASSWORD,
                null);

            registeredTask.Run(null);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void TryLaunchWithLogonUserInActiveSession(string commandLine, bool createConsole)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF)
        {
            throw new InvalidOperationException("No active session found.");
        }

        var credentials = GetServiceCredentials();
        if (string.IsNullOrWhiteSpace(credentials.userName) || string.IsNullOrWhiteSpace(credentials.password))
        {
            throw new InvalidOperationException("Service credentials not found in HKLM\\SOFTWARE\\AppElevator.");
        }

        var (user, domain) = SplitUserDomain(credentials.userName);

        if (!LogonUser(user, domain, credentials.password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out var logonToken))
        {
            throw new InvalidOperationException($"LogonUser failed: {Marshal.GetLastWin32Error()}");
        }

        IntPtr winsta = IntPtr.Zero;
        IntPtr desktop = IntPtr.Zero;

        try
        {
            var identityName = new WindowsIdentity(logonToken).Name ?? string.Empty;
            if (!identityName.Equals(credentials.userName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"LogonUser returned unexpected identity '{identityName}'.");
            }

            GrantDesktopAccess(credentials.userName);

            winsta = OpenWindowStation("WinSta0", false, WINSTA_ALL_ACCESS);
            desktop = OpenDesktop("Default", 0, false, DESKTOP_ALL_ACCESS);
            if (winsta != IntPtr.Zero)
            {
                SetProcessWindowStation(winsta);
            }

            if (desktop != IntPtr.Zero)
            {
                SetThreadDesktop(desktop);
            }

            var desiredAccess = (TokenAccessLevels)(TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
            if (!DuplicateTokenEx(logonToken, desiredAccess, IntPtr.Zero,
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
                    var profile = new PROFILEINFO
                    {
                        dwSize = Marshal.SizeOf<PROFILEINFO>(),
                        lpUserName = user
                    };

                    LoadUserProfile(primaryToken, ref profile);

                    var startupInfo = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFO>(),
                        lpDesktop = "winsta0\\default"
                    };

                    var procInfo = new PROCESS_INFORMATION();
                    var creationFlags = CREATE_UNICODE_ENVIRONMENT | (createConsole ? CREATE_NEW_CONSOLE : 0);

                    if (!CreateProcessAsUser(primaryToken, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                            creationFlags, environment, null, ref startupInfo, out procInfo))
                    {
                        throw new InvalidOperationException($"CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");
                    }

                    WriteServiceLog($"Launched with session {sessionId}.");

                    CloseHandle(procInfo.hThread);
                    CloseHandle(procInfo.hProcess);

                    WriteServiceLog($"Launched '{commandLine}' as {identityName} (PID {procInfo.dwProcessId}).");

                    if (profile.hProfile != IntPtr.Zero)
                    {
                        UnloadUserProfile(primaryToken, profile.hProfile);
                    }

                    return;
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
            if (desktop != IntPtr.Zero)
            {
                CloseHandle(desktop);
            }

            if (winsta != IntPtr.Zero)
            {
                CloseHandle(winsta);
            }

            CloseHandle(logonToken);
        }
    }

    private static void WriteServiceLog(string message)
    {
        try
        {
            EventLog.WriteEntry(Constants.EventSource, message, EventLogEntryType.Information, Constants.ServiceLogEventId);
        }
        catch
        {
            // Ignore logging errors.
        }
    }

    private static (string user, string domain) SplitUserDomain(string account)
    {
        var parts = account.Split('\\');
        if (parts.Length == 2)
        {
            return (parts[1], parts[0]);
        }

        return (account, ".");
    }


    private static void GrantDesktopAccess(string account)
    {
        var sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));

        var winsta = OpenWindowStation("WinSta0", false, READ_CONTROL | WRITE_DAC);
        if (winsta != IntPtr.Zero)
        {
            try
            {
                UpdateUserObjectSecurity(winsta, WINSTA_ALL_ACCESS, sid);
            }
            finally
            {
                CloseHandle(winsta);
            }
        }

        var desktop = OpenDesktop("Default", 0, false, READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
        if (desktop != IntPtr.Zero)
        {
            try
            {
                UpdateUserObjectSecurity(desktop, DESKTOP_ALL_ACCESS, sid);
            }
            finally
            {
                CloseHandle(desktop);
            }
        }
    }

    private static void UpdateUserObjectSecurity(IntPtr handle, uint accessMask, SecurityIdentifier sid)
    {
        var securityInfo = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        GetUserObjectSecurity(handle, ref securityInfo, null, 0, out var lengthNeeded);
        if (lengthNeeded == 0)
        {
            return;
        }

        var buffer = new byte[lengthNeeded];
        if (!GetUserObjectSecurity(handle, ref securityInfo, buffer, lengthNeeded, out _))
        {
            return;
        }

        var raw = new RawSecurityDescriptor(buffer, 0);
        var dacl = raw.DiscretionaryAcl ?? new RawAcl(2, 1);

        var hasAccess = dacl.Cast<GenericAce>()
            .OfType<CommonAce>()
            .Any(ace =>
                ace.SecurityIdentifier.Equals(sid) &&
                (ace.AccessMask & accessMask) == accessMask &&
                ace.AceQualifier == AceQualifier.AccessAllowed);

        if (!hasAccess)
        {
            dacl.InsertAce(dacl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, (int)accessMask, sid, false, null));
            raw.DiscretionaryAcl = dacl;
            var newBuffer = new byte[raw.BinaryLength];
            raw.GetBinaryForm(newBuffer, 0);
            SetUserObjectSecurity(handle, ref securityInfo, newBuffer);
        }
    }

    private static string GetActiveSessionUser(uint sessionId)
    {
        var userName = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSUserName);
        var domain = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSDomainName);

        if (string.IsNullOrWhiteSpace(userName))
        {
            return string.Empty;
        }

        return string.IsNullOrWhiteSpace(domain) ? userName : $"{domain}\\{userName}";
    }

    private static string QuerySessionString(uint sessionId, WTS_INFO_CLASS infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytes))
        {
            return string.Empty;
        }

        try
        {
            if (bytes <= 1)
            {
                return string.Empty;
            }

            return Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static (string path, string args) SplitCommandLine(string commandLine)
    {
        var trimmed = commandLine.Trim();
        var spaceIndex = trimmed.IndexOf(' ');
        if (spaceIndex <= 0)
        {
            return (trimmed, string.Empty);
        }

        return (trimmed[..spaceIndex], trimmed[(spaceIndex + 1)..]);
    }

    private static (string userName, string password) GetServiceCredentials()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\AppElevator");
            if (key == null)
            {
                return (string.Empty, string.Empty);
            }

            var user = key.GetValue("ServiceUser") as string ?? string.Empty;
            var password = key.GetValue("ServicePasswordPlain") as string ?? string.Empty;
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password))
            {
                return (string.Empty, string.Empty);
            }
            return (user, password);
        }
        catch
        {
            return (string.Empty, string.Empty);
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
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;

    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOW = 5;


    private const uint READ_CONTROL = 0x00020000;
    private const uint WRITE_DAC = 0x00040000;
    private const uint DESKTOP_READOBJECTS = 0x0001;
    private const uint DESKTOP_WRITEOBJECTS = 0x0080;
    private const uint WINSTA_ALL_ACCESS = 0x000F037F;
    private const uint DESKTOP_ALL_ACCESS = 0x000F01FF;

    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_PROVIDER_DEFAULT = 0;

    private const int TASK_ACTION_EXEC = 0;
    private const int TASK_LOGON_PASSWORD = 1;
    private const int TASK_RUNLEVEL_HIGHEST = 1;
    private const int TASK_CREATE_OR_UPDATE = 6;

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        public string? lpUserName;
        public string? lpProfilePath;
        public string? lpDefaultPath;
        public string? lpServerName;
        public string? lpPolicyPath;
        public IntPtr hProfile;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

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

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);


    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, byte[]? pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, byte[] pSecurityDescriptor);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessWindowStation(IntPtr hWinSta);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetThreadDesktop(IntPtr hDesktop);

    [Flags]
    private enum SECURITY_INFORMATION : uint
    {
        DACL_SECURITY_INFORMATION = 0x00000004
    }

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

    private static string GetUserNameFromToken(IntPtr token)
    {
        using var identity = new WindowsIdentity(token);
        return identity.Name?.Split('\\').Last() ?? string.Empty;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSDomainName = 7
    }
}
