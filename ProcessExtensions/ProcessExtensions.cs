using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions
{
    public class ProcessCreationException : Exception
    {
        public ProcessCreationException(string msg) : base(msg) { }
    }

    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const int STARTF_USESHOWWINDOW = 0x00000001;

        private const uint TOKEN_ALL_ACCESS = 0xF01FF;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            out IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        [DllImport("Wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr ppSessionInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, ref int tokenInformation, int tokenInformationLength);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {

            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            int iResultOfCreateProcessAsUser;

            var pEnv = IntPtr.Zero;
            IntPtr currentProcessToken = IntPtr.Zero;
            IntPtr duplicatedToken;

            uint interactiveSessionId = WTSGetActiveConsoleSessionId();

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {

                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ALL_ACCESS, out currentProcessToken))
                {
                    throw new Exception("OpenProcessToken failed. Error: " + Marshal.GetLastWin32Error());
                }

                if (!DuplicateTokenEx(currentProcessToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                (int)TOKEN_TYPE.TokenPrimary,
                out duplicatedToken))
                {
                    throw new Exception("DuplicateTokenEx failed. Error: " + Marshal.GetLastWin32Error());
                }
                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.dwFlags = STARTF_USESHOWWINDOW;
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, duplicatedToken, false))
                {
                    throw new ProcessCreationException("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (workDir != null)
                {
                    Directory.SetCurrentDirectory(workDir);
                }

                int uiValue = 1;
                IntPtr pUIValue = Marshal.AllocHGlobal(sizeof(int));
                Marshal.WriteInt32(pUIValue, uiValue);

                int sessionId = (int)interactiveSessionId;
                if (!SetTokenInformation(duplicatedToken, 12, ref sessionId, sizeof(int)))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new ProcessCreationException("StartProcessAsCurrentUser: SetTokenInformation failed. Error Code - " + iResultOfCreateProcessAsUser);
                }

                if (!CreateProcessAsUser(duplicatedToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new ProcessCreationException("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code -" + iResultOfCreateProcessAsUser);
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(currentProcessToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return true;
        }

    }
}
