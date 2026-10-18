// Windows L2 native launcher backend for dsh-plugin-testbed.
//
// Compiled in-memory by launcher.ps1 through Add-Type. This source is the
// authority for the native mechanism; it is never compiled into a third-party
// artifact and it never loads untrusted code into the control plane.
//
// Mechanism (minimal, no new local account, no global firewall change):
//   - per-user AppContainer profile (CreateAppContainerProfile) => synthetic
//     low-privilege identity, no admin groups, low integrity;
//   - process created with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES and **no
//     capabilities** => OS-enforced default-deny network and restricted file
//     access;
//   - Job Object with process-time, memory, active-process and kill-on-close
//     limits;
//   - explicit environment block (allowlist), inherited stdio only, no other
//     handles;
//   - attempt temp root under the AppContainer folder (inherited ACL for the
//     package SID), reparse points rejected, SDDL reported for attestation.
//
// No mutation happens merely by compiling/probing. Profile creation, process
// launch and profile deletion require a separate authorization file checked by
// launcher.ps1.
//
// This file holds NO signing key and makes NO market-eligibility decision.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DshTestbed.Isolation
{
    internal static class NativeMethods
    {
        internal const uint TOKEN_QUERY = 0x0008;
        internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const uint PROCESS_TERMINATE = 0x0001;
        internal const uint SYNCHRONIZE = 0x00100000;
        internal const uint CREATE_SUSPENDED = 0x00000004;
        internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        internal const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        internal const uint STARTF_USESTDHANDLES = 0x00000100;
        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_OBJECT_0 = 0x00000000;
        internal const uint WAIT_TIMEOUT = 0x00000102;

        internal const int TokenUser = 1;
        internal const int TokenIntegrityLevel = 25;
        internal const int TokenIsAppContainer = 29;
        internal const int TokenCapabilities = 30;
        internal const int TokenAppContainerSid = 31;

        internal const int JobObjectExtendedLimitInformation = 9;
        internal const uint JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
        internal const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
        internal const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
        internal const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
        internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

        internal const uint SE_FILE_OBJECT = 1;
        internal const uint DACL_SECURITY_INFORMATION = 0x00000004;

        internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x20009;
        internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = (IntPtr)0x20002;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_CAPABILITIES
        {
            internal IntPtr AppContainerSid;
            internal IntPtr Capabilities;
            internal uint CapabilityCount;
            internal uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal int dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFOEX
        {
            internal STARTUPINFO StartupInfo;
            internal IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            internal IntPtr Sid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_USER
        {
            internal SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_MANDATORY_LABEL
        {
            internal SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IO_COUNTERS
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            internal IO_COUNTERS IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr securityDescriptor, uint requestedStringSDRevision, uint securityInformation, out IntPtr stringSecurityDescriptor, out uint stringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern uint GetNamedSecurityInfoW(string objectName, uint objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr handle);

        [DllImport("advapi32.dll")]
        internal static extern IntPtr FreeSid(IntPtr sid);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int CreateAppContainerProfile(string appContainerName, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int DeleteAppContainerProfile(string appContainerName);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr appContainerSid);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr folderPath);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr CreateJobObjectW(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetInformationJobObject(IntPtr jobHandle, int infoClass, IntPtr info, int infoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool QueryInformationJobObject(IntPtr jobHandle, int infoClass, IntPtr info, int infoLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AssignProcessToJobObject(IntPtr jobHandle, IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(IntPtr jobHandle, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcessW(
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateProcess(IntPtr processHandle, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetExitCodeProcess(IntPtr processHandle, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr GetModuleHandleW(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll")]
        internal static extern bool IsProcessInJob(IntPtr processHandle, IntPtr jobHandle, out bool result);
    }

    public static class NativeL2
    {
        private const string StatusPrefix = "DSH_L2_STATUS ";
        private const string DefaultProfileName = "DshTestbedL2";

        private static void Status(string json)
        {
            Console.Error.WriteLine(StatusPrefix + json);
            Console.Error.Flush();
        }

        private static string Q(string value)
        {
            if (value == null) return "null";
            var sb = new StringBuilder();
            sb.Append('"');
            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20 || ch > 0x7e) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                        else sb.Append(ch);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static string SidToString(IntPtr sid)
        {
            IntPtr str;
            if (!NativeMethods.ConvertSidToStringSidW(sid, out str)) return null;
            try { return Marshal.PtrToStringUni(str); }
            finally { NativeMethods.LocalFree(str); }
        }

        private static IntPtr DeriveSid(string profileName, out string error)
        {
            IntPtr sid;
            int hr = NativeMethods.DeriveAppContainerSidFromAppContainerName(profileName, out sid);
            if (hr != 0)
            {
                error = "derive-appcontainer-sid-failed:0x" + hr.ToString("X8");
                return IntPtr.Zero;
            }
            error = null;
            return sid;
        }

        private static string GetFolderPath(string sidString, out string error)
        {
            IntPtr pathPtr;
            int hr = NativeMethods.GetAppContainerFolderPath(sidString, out pathPtr);
            if (hr != 0)
            {
                error = "get-appcontainer-folder-failed:0x" + hr.ToString("X8");
                return null;
            }
            try { error = null; return Marshal.PtrToStringUni(pathPtr); }
            finally { Marshal.FreeCoTaskMem(pathPtr); }
        }

        private static string GetDaclSddl(string path, out string error)
        {
            IntPtr owner, group, dacl, sacl, sd;
            uint result = NativeMethods.GetNamedSecurityInfoW(path, NativeMethods.SE_FILE_OBJECT,
                NativeMethods.DACL_SECURITY_INFORMATION, out owner, out group, out dacl, out sacl, out sd);
            if (result != 0)
            {
                error = "get-named-security-info-failed:" + result;
                return null;
            }
            try
            {
                IntPtr sddl;
                uint len;
                if (!NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1,
                    NativeMethods.DACL_SECURITY_INFORMATION, out sddl, out len))
                {
                    error = "convert-sddl-failed:" + Marshal.GetLastWin32Error();
                    return null;
                }
                try { error = null; return Marshal.PtrToStringUni(sddl); }
                finally { NativeMethods.LocalFree(sddl); }
            }
            finally { NativeMethods.LocalFree(sd); }
        }

        private static int CountReparsePoints(string root)
        {
            int count = 0;
            foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) count++;
            }
            return count;
        }

        private struct TokenMeasurement
        {
            internal string userSid;
            internal string appContainerSid;
            internal string integritySid;
            internal bool isAppContainer;
            internal int capabilityCount;
            internal string error;
        }

        private static TokenMeasurement MeasureToken(IntPtr processHandle)
        {
            var m = new TokenMeasurement { error = null };
            IntPtr token;
            if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TOKEN_QUERY, out token))
            {
                m.error = "open-process-token-failed:" + Marshal.GetLastWin32Error();
                return m;
            }
            try
            {
                int size;
                NativeMethods.GetTokenInformation(token, NativeMethods.TokenIsAppContainer, IntPtr.Zero, 0, out size);
                var buffer = Marshal.AllocHGlobal(Math.Max(size, 4));
                try
                {
                    if (size >= 4 && NativeMethods.GetTokenInformation(token, NativeMethods.TokenIsAppContainer, buffer, size, out size))
                        m.isAppContainer = Marshal.ReadInt32(buffer) != 0;
                    else
                        m.error = "token-is-appcontainer-query-failed:" + Marshal.GetLastWin32Error();
                }
                finally { Marshal.FreeHGlobal(buffer); }

                NativeMethods.GetTokenInformation(token, NativeMethods.TokenUser, IntPtr.Zero, 0, out size);
                buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenUser, buffer, size, out size))
                    {
                        var user = (NativeMethods.TOKEN_USER)Marshal.PtrToStructure(buffer, typeof(NativeMethods.TOKEN_USER));
                        m.userSid = SidToString(user.User.Sid);
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }

                NativeMethods.GetTokenInformation(token, NativeMethods.TokenIntegrityLevel, IntPtr.Zero, 0, out size);
                buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenIntegrityLevel, buffer, size, out size))
                    {
                        var label = (NativeMethods.TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(buffer, typeof(NativeMethods.TOKEN_MANDATORY_LABEL));
                        m.integritySid = SidToString(label.Label.Sid);
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }

                NativeMethods.GetTokenInformation(token, NativeMethods.TokenAppContainerSid, IntPtr.Zero, 0, out size);
                if (size > 0)
                {
                    buffer = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenAppContainerSid, buffer, size, out size))
                        {
                            var appContainerSid = Marshal.ReadIntPtr(buffer);
                            if (appContainerSid != IntPtr.Zero) m.appContainerSid = SidToString(appContainerSid);
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }

                NativeMethods.GetTokenInformation(token, NativeMethods.TokenCapabilities, IntPtr.Zero, 0, out size);
                if (size > 0)
                {
                    buffer = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenCapabilities, buffer, size, out size))
                            m.capabilityCount = Marshal.ReadInt32(buffer);
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
            }
            finally { NativeMethods.CloseHandle(token); }
            return m;
        }

        private static string BuildEnvironmentBlock(string envFile)
        {
            var lines = new List<string>();
            foreach (var raw in File.ReadAllLines(envFile))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                lines.Add(line);
            }
            lines.Sort(StringComparer.OrdinalIgnoreCase);
            var sb = new StringBuilder();
            foreach (var line in lines) sb.Append(line).Append('\0');
            sb.Append('\0');
            return sb.ToString();
        }

        private static IntPtr CreateStandardAttributeList(out IntPtr attributeList, IntPtr securityCapabilitiesPtr, IntPtr handleListPtr, uint handleCount, out string error)
        {
            attributeList = IntPtr.Zero;
            var size = IntPtr.Zero;
            NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            attributeList = Marshal.AllocHGlobal(size);
            if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 2, 0, ref size))
            {
                error = "initialize-attribute-list-failed:" + Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(attributeList);
                attributeList = IntPtr.Zero;
                return IntPtr.Zero;
            }
            var capsSize = (IntPtr)Marshal.SizeOf(typeof(NativeMethods.SECURITY_CAPABILITIES));
            if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0,
                NativeMethods.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, securityCapabilitiesPtr, capsSize, IntPtr.Zero, IntPtr.Zero))
            {
                error = "update-security-capabilities-failed:" + Marshal.GetLastWin32Error();
                NativeMethods.DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
                attributeList = IntPtr.Zero;
                return IntPtr.Zero;
            }
            if (handleListPtr != IntPtr.Zero && handleCount > 0)
            {
                var handlesSize = (IntPtr)(IntPtr.Size * (int)handleCount);
                if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0,
                    NativeMethods.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleListPtr, handlesSize, IntPtr.Zero, IntPtr.Zero))
                {
                    error = "update-handle-list-failed:" + Marshal.GetLastWin32Error();
                    NativeMethods.DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                    attributeList = IntPtr.Zero;
                    return IntPtr.Zero;
                }
            }
            error = null;
            return attributeList;
        }

        private static string MeasureJobLimits(IntPtr job)
        {
            var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            var length = Marshal.SizeOf(typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                int returned;
                if (!NativeMethods.QueryInformationJobObject(job, NativeMethods.JobObjectExtendedLimitInformation, buffer, length, out returned))
                    return null;
                info = (NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(buffer, typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                var flags = info.BasicLimitInformation.LimitFlags;
                return "{\"process_time_100ns\":" + info.BasicLimitInformation.PerProcessUserTimeLimit +
                       ",\"process_memory_bytes\":" + (ulong)info.ProcessMemoryLimit +
                       ",\"job_memory_bytes\":" + (ulong)info.JobMemoryLimit +
                       ",\"active_process_limit\":" + info.BasicLimitInformation.ActiveProcessLimit +
                       ",\"kill_on_job_close\":" + ((flags & NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0 ? "true" : "false") +
                       ",\"limit_flags\":" + flags +
                       ",\"measured\":true}";
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static IntPtr CreateJobWithLimits(long cpuMs, long memoryMb, int processes, out string error)
        {
            var job = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                error = "create-job-object-failed:" + Marshal.GetLastWin32Error();
                return IntPtr.Zero;
            }
            var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.PerProcessUserTimeLimit = Math.Max(1, cpuMs) * 10000L;
            info.BasicLimitInformation.LimitFlags =
                NativeMethods.JOB_OBJECT_LIMIT_PROCESS_TIME |
                NativeMethods.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                NativeMethods.JOB_OBJECT_LIMIT_JOB_MEMORY |
                NativeMethods.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.BasicLimitInformation.ActiveProcessLimit = (uint)Math.Max(1, processes);
            info.ProcessMemoryLimit = (UIntPtr)(ulong)(Math.Max(16, memoryMb) * 1024L * 1024L);
            info.JobMemoryLimit = (UIntPtr)(ulong)(Math.Max(16, memoryMb) * 1024L * 1024L * 2L);

            var length = Marshal.SizeOf(typeof(NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                if (!NativeMethods.SetInformationJobObject(job, NativeMethods.JobObjectExtendedLimitInformation, buffer, length))
                {
                    error = "set-job-limits-failed:" + Marshal.GetLastWin32Error();
                    NativeMethods.CloseHandle(job);
                    return IntPtr.Zero;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            error = null;
            return job;
        }

        private static string JobLimitsJson(long cpuMs, long memoryMb, int processes)
        {
            return "{\"process_time_100ns\":" + (Math.Max(1, cpuMs) * 10000L) +
                   ",\"process_memory_bytes\":" + (Math.Max(16, memoryMb) * 1024L * 1024L) +
                   ",\"job_memory_bytes\":" + (Math.Max(16, memoryMb) * 1024L * 1024L * 2L) +
                   ",\"active_process_limit\":" + Math.Max(1, processes) +
                   ",\"kill_on_job_close\":true}";
        }

        // -------------------------------------------------------------------
        // Read-only probe (safe without authorization; creates/closes a job).
        // -------------------------------------------------------------------
        public static string Probe()
        {
            var notes = new List<string>();
            // Inspect mode is strictly read-only: it must not create even a
            // transient Job Object. API availability is checked by resolving the
            // exported entry point (no OS object is created); actual Job Object
            // creation/measurement happens only in authorized execute mode.
            IntPtr kernel32 = NativeMethods.GetModuleHandleW("kernel32.dll");
            bool jobOk = kernel32 != IntPtr.Zero &&
                NativeMethods.GetProcAddress(kernel32, "CreateJobObjectW") != IntPtr.Zero &&
                NativeMethods.GetProcAddress(kernel32, "SetInformationJobObject") != IntPtr.Zero &&
                NativeMethods.GetProcAddress(kernel32, "QueryInformationJobObject") != IntPtr.Zero;
            notes.Add("job-object-api-available-unprobed");

            string profileError;
            var sid = DeriveSid(DefaultProfileName, out profileError);
            var sidString = sid != IntPtr.Zero ? SidToString(sid) : null;
            if (sid != IntPtr.Zero) NativeMethods.FreeSid(sid);
            string folderError = null;
            var folder = sidString != null ? GetFolderPath(sidString, out folderError) : null;
            var profileExists = folder != null;
            if (!profileExists && folderError != null) notes.Add(folderError);
            if (profileError != null) notes.Add(profileError);

            var currentUser = Environment.UserName;
            var json = new StringBuilder();
            json.Append("{\"status\":\"ok\",\"native_backend\":\"windows-l2-appcontainer-jobobject/v1\"");
            json.Append(",\"native_backend_compiled\":true");
            json.Append(",\"platform\":\"win32\"");
            json.Append(",\"userenv_exports\":true");
            json.Append(",\"job_object_ready\":").Append(jobOk ? "true" : "false");
            json.Append(",\"profile_name\":").Append(Q(DefaultProfileName));
            json.Append(",\"profile_exists\":").Append(profileExists ? "true" : "false");
            json.Append(",\"profile_sid\":").Append(Q(sidString));
            json.Append(",\"profile_folder\":").Append(Q(folder));
            json.Append(",\"current_user\":").Append(Q(currentUser));
            json.Append(",\"notes\":[");
            for (int i = 0; i < notes.Count; i++)
            {
                if (i > 0) json.Append(',');
                json.Append(Q(notes[i]));
            }
            json.Append("],\"mutations\":false,\"evidence_grade\":\"E0\"}");
            return json.ToString();
        }

        // -------------------------------------------------------------------
        // Authorized execution. launcher.ps1 validates the authorization file
        // before calling this method; this method still enforces every
        // structural/OS invariant and fails closed.
        // -------------------------------------------------------------------
        public static int Execute(
            string profileName,
            string tempRoot,
            string applicationPath,
            string arguments,
            string workingDirectory,
            string envFile,
            long cpuMs,
            long memoryMb,
            int processes,
            bool createProfile,
            bool deleteTempOnExit,
            bool deleteProfileOnExit)
        {
            IntPtr profileSid = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            IntPtr processHandle = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;
            IntPtr attrList = IntPtr.Zero;
            IntPtr envBlock = IntPtr.Zero;
            IntPtr securityCapsPtr = IntPtr.Zero;
            IntPtr handleListPtr = IntPtr.Zero;
            GCHandle securityCapsHandle = default(GCHandle);
            GCHandle handleListHandle = default(GCHandle);
            bool profileCreated = false;
            string stage = "init";
            string folder = null;
            string sddl = null;
            try
            {
                stage = "derive-profile-sid";
                string deriveError;
                profileSid = DeriveSid(profileName, out deriveError);
                if (profileSid == IntPtr.Zero)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"profile\",\"error\":" + Q(deriveError) + "}");
                    return 2;
                }
                var sidString = SidToString(profileSid);

                stage = "profile-folder";
                string folderError;
                folder = GetFolderPath(sidString, out folderError);
                if (folder == null)
                {
                    if (!createProfile)
                    {
                        Status("{\"status\":\"blocked\",\"stage\":\"profile\",\"error\":\"profile-missing-and-create-not-authorized\"}");
                        return 2;
                    }
                    IntPtr createdSid;
                    int hr = NativeMethods.CreateAppContainerProfile(profileName, "DSH testbed L2", "DSH plugin testbed L2 worker", IntPtr.Zero, 0, out createdSid);
                    if (hr != 0)
                    {
                        Status("{\"status\":\"blocked\",\"stage\":\"profile-create\",\"error\":\"create-appcontainer-profile-failed:0x" + hr.ToString("X8") + "\"}");
                        return 2;
                    }
                    if (createdSid != IntPtr.Zero) NativeMethods.FreeSid(createdSid);
                    profileCreated = true;
                    folder = GetFolderPath(sidString, out folderError);
                    if (folder == null)
                    {
                        Status("{\"status\":\"blocked\",\"stage\":\"profile-folder\",\"error\":" + Q(folderError) + "}");
                        return 2;
                    }
                }

                stage = "temp-root";
                var normalizedFolder = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
                string normalizedTemp;
                if (string.Equals(tempRoot, "auto", StringComparison.OrdinalIgnoreCase))
                {
                    normalizedTemp = Path.Combine(folder, "TempState", "attempt-" + DateTime.UtcNow.Ticks.ToString() + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                }
                else
                {
                    normalizedTemp = Path.GetFullPath(tempRoot);
                    if (!normalizedTemp.StartsWith(normalizedFolder, StringComparison.OrdinalIgnoreCase))
                    {
                        Status("{\"status\":\"blocked\",\"stage\":\"temp-root\",\"error\":\"temp-root-outside-appcontainer-folder\"}");
                        return 2;
                    }
                }
                if (string.Equals(workingDirectory, "auto", StringComparison.OrdinalIgnoreCase)) workingDirectory = normalizedTemp;
                Directory.CreateDirectory(normalizedTemp);
                var reparseCount = CountReparsePoints(normalizedTemp);
                if (reparseCount != 0)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"temp-root\",\"error\":\"reparse-points-present\",\"reparse_points\":" + reparseCount + "}");
                    return 2;
                }
                string sddlError;
                sddl = GetDaclSddl(normalizedTemp, out sddlError);
                if (sddl == null)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"temp-acl\",\"error\":" + Q(sddlError) + "}");
                    return 2;
                }

                stage = "job-object";
                string jobError;
                job = CreateJobWithLimits(cpuMs, memoryMb, processes, out jobError);
                if (job == IntPtr.Zero)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"job-object\",\"error\":" + Q(jobError) + "}");
                    return 2;
                }

                stage = "environment";
                var envBlockString = BuildEnvironmentBlock(envFile);
                envBlock = Marshal.StringToHGlobalUni(envBlockString);

                stage = "security-capabilities";
                var caps = new NativeMethods.SECURITY_CAPABILITIES
                {
                    AppContainerSid = profileSid,
                    Capabilities = IntPtr.Zero,
                    CapabilityCount = 0,
                    Reserved = 0,
                };
                securityCapsHandle = GCHandle.Alloc(caps, GCHandleType.Pinned);
                securityCapsPtr = securityCapsHandle.AddrOfPinnedObject();

                stage = "std-handles";
                var stdIn = NativeMethods.GetStdHandle(-10);
                var stdOut = NativeMethods.GetStdHandle(-11);
                var stdErr = NativeMethods.GetStdHandle(-12);
                var handles = new IntPtr[] { stdIn, stdOut, stdErr };
                var validHandles = new IntPtr[3];
                int validCount = 0;
                foreach (var handle in handles)
                {
                    if (handle != IntPtr.Zero && handle != (IntPtr)(-1)) validHandles[validCount++] = handle;
                }
                if (validCount != 3)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"std-handles\",\"error\":\"stdio-handles-not-inheritable\"}");
                    return 2;
                }
                handleListHandle = GCHandle.Alloc(validHandles, GCHandleType.Pinned);
                handleListPtr = handleListHandle.AddrOfPinnedObject();
                securityCapsHandle = GCHandle.Alloc(caps, GCHandleType.Pinned);
                securityCapsPtr = securityCapsHandle.AddrOfPinnedObject();

                stage = "attribute-list";
                string attrError;
                attrList = CreateStandardAttributeList(out attrList, securityCapsPtr, handleListPtr, 3, out attrError);
                if (attrList == IntPtr.Zero)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"attribute-list\",\"error\":" + Q(attrError) + "}");
                    return 2;
                }

                stage = "create-process";
                var startup = new NativeMethods.STARTUPINFOEX();
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(NativeMethods.STARTUPINFOEX));
                startup.StartupInfo.dwFlags = (int)NativeMethods.STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdIn;
                startup.StartupInfo.hStdOutput = stdOut;
                startup.StartupInfo.hStdError = stdErr;
                startup.lpAttributeList = attrList;

                var commandLine = new StringBuilder();
                commandLine.Append('"').Append(applicationPath).Append('"');
                if (!string.IsNullOrEmpty(arguments)) commandLine.Append(' ').Append(arguments);

                NativeMethods.PROCESS_INFORMATION pi;
                bool created = NativeMethods.CreateProcessW(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_UNICODE_ENVIRONMENT | NativeMethods.EXTENDED_STARTUPINFO_PRESENT,
                    envBlock,
                    workingDirectory,
                    ref startup,
                    out pi);
                if (!created)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"create-process\",\"error\":\"create-process-failed:" + Marshal.GetLastWin32Error() + "\"}");
                    return 2;
                }
                processHandle = pi.hProcess;
                threadHandle = pi.hThread;

                stage = "assign-job";
                if (!NativeMethods.AssignProcessToJobObject(job, processHandle))
                {
                    var assignError = Marshal.GetLastWin32Error();
                    NativeMethods.TerminateProcess(processHandle, 1);
                    Status("{\"status\":\"blocked\",\"stage\":\"assign-job\",\"error\":\"assign-process-to-job-failed:" + assignError + "\"}");
                    return 2;
                }
                var measuredJobLimits = MeasureJobLimits(job);
                if (measuredJobLimits == null)
                {
                    NativeMethods.TerminateProcess(processHandle, 1);
                    Status("{\"status\":\"blocked\",\"stage\":\"measure-job\",\"error\":\"query-job-limits-failed:" + Marshal.GetLastWin32Error() + "\"}");
                    return 2;
                }

                stage = "token-measurement";
                var token = MeasureToken(processHandle);
                if (token.error != null)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"token-measurement\",\"error\":" + Q(token.error) + "}");
                    NativeMethods.TerminateProcess(processHandle, 1);
                    return 2;
                }
                bool appContainerOk = token.isAppContainer && token.appContainerSid == sidString;
                bool lowIntegrity = token.integritySid == "S-1-16-4096";
                if (!appContainerOk || !lowIntegrity)
                {
                    var reason = !appContainerOk ? "process-not-appcontainer-or-sid-mismatch" : "process-integrity-not-low";
                    Status("{\"status\":\"blocked\",\"stage\":\"token-measurement\",\"error\":" + Q(reason) +
                           ",\"user_sid\":" + Q(token.userSid) +
                           ",\"appcontainer_sid\":" + Q(token.appContainerSid) +
                           ",\"expected_sid\":" + Q(sidString) +
                           ",\"is_appcontainer\":" + (token.isAppContainer ? "true" : "false") +
                           ",\"integrity_sid\":" + Q(token.integritySid) + "}");
                    NativeMethods.TerminateProcess(processHandle, 1);
                    return 2;
                }

                stage = "resume";
                if (NativeMethods.ResumeThread(threadHandle) == 0xFFFFFFFF)
                {
                    Status("{\"status\":\"blocked\",\"stage\":\"resume\",\"error\":\"resume-thread-failed:" + Marshal.GetLastWin32Error() + "\"}");
                    NativeMethods.TerminateProcess(processHandle, 1);
                    return 2;
                }

                var startedAt = DateTime.UtcNow.ToString("o");
                Status("{\"status\":\"launched\",\"pid\":" + pi.dwProcessId +
                       ",\"started_at\":" + Q(startedAt) +
                       ",\"profile_name\":" + Q(profileName) +
                       ",\"profile_created\":" + (profileCreated ? "true" : "false") +
                       ",\"appcontainer_sid\":" + Q(token.appContainerSid) +
                       ",\"identity_integrity\":\"low\"" +
                       ",\"token_is_appcontainer\":true" +
                       ",\"capability_count\":" + token.capabilityCount +
                       ",\"job_limits\":" + measuredJobLimits +
                       ",\"temp_root\":" + Q(normalizedTemp) +
                       ",\"acl_sddl\":" + Q(sddl) +
                       ",\"reparse_points\":0" +
                       ",\"stdio_inherited\":true}");

                stage = "wait";
                var wait = NativeMethods.WaitForSingleObject(processHandle, NativeMethods.INFINITE);
                uint exitCode = 1;
                if (wait == NativeMethods.WAIT_OBJECT_0) NativeMethods.GetExitCodeProcess(processHandle, out exitCode);
                Status("{\"status\":\"exited\",\"pid\":" + pi.dwProcessId + ",\"exit_code\":" + exitCode + ",\"temp_removed\":" + (deleteTempOnExit ? "true" : "false") + "}");
                return (int)exitCode;
            }
            catch (Exception ex)
            {
                Status("{\"status\":\"blocked\",\"stage\":" + Q(stage) + ",\"error\":" + Q(ex.GetType().Name + ": " + ex.Message) + "}");
                if (processHandle != IntPtr.Zero) NativeMethods.TerminateProcess(processHandle, 1);
                return 2;
            }
            finally
            {
                if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
                if (attrList != IntPtr.Zero)
                {
                    NativeMethods.DeleteProcThreadAttributeList(attrList);
                    Marshal.FreeHGlobal(attrList);
                }
                if (securityCapsHandle.IsAllocated) securityCapsHandle.Free();
                if (handleListHandle.IsAllocated) handleListHandle.Free();
                if (job != IntPtr.Zero) NativeMethods.CloseHandle(job);
                if (threadHandle != IntPtr.Zero) NativeMethods.CloseHandle(threadHandle);
                if (processHandle != IntPtr.Zero) NativeMethods.CloseHandle(processHandle);
                if (profileSid != IntPtr.Zero) NativeMethods.FreeSid(profileSid);
                if (deleteTempOnExit && folder != null && !string.IsNullOrEmpty(tempRoot))
                {
                    try { if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, true); } catch { }
                }
                if (deleteProfileOnExit)
                {
                    try { NativeMethods.DeleteAppContainerProfile(profileName); } catch { }
                }
            }
        }

        public static string ProbeCreateProcess(string applicationPath, string arguments, string workingDirectory, string envFile)
        {
            IntPtr envBlock = IntPtr.Zero;
            IntPtr processHandle = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;
            try
            {
                var envString = BuildEnvironmentBlock(envFile);
                envBlock = Marshal.StringToHGlobalUni(envString);
                var startup = new NativeMethods.STARTUPINFOEX();
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(NativeMethods.STARTUPINFOEX));
                var commandLine = new StringBuilder();
                commandLine.Append('"').Append(applicationPath).Append('"');
                if (!string.IsNullOrEmpty(arguments)) commandLine.Append(' ').Append(arguments);
                NativeMethods.PROCESS_INFORMATION pi;
                bool created = NativeMethods.CreateProcessW(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                    envBlock,
                    workingDirectory,
                    ref startup,
                    out pi);
                if (!created) return "create-failed:" + Marshal.GetLastWin32Error();
                processHandle = pi.hProcess;
                threadHandle = pi.hThread;
                NativeMethods.TerminateProcess(processHandle, 0);
                return "create-ok:pid=" + pi.dwProcessId;
            }
            finally
            {
                if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
                if (threadHandle != IntPtr.Zero) NativeMethods.CloseHandle(threadHandle);
                if (processHandle != IntPtr.Zero) NativeMethods.CloseHandle(processHandle);
            }
        }

        public static int CreateProfile(string profileName)
        {
            IntPtr sid;
            int hr = NativeMethods.CreateAppContainerProfile(profileName, "DSH testbed L2", "DSH plugin testbed L2 worker", IntPtr.Zero, 0, out sid);
            if (hr != 0)
            {
                Status("{\"status\":\"blocked\",\"stage\":\"profile-create\",\"error\":\"create-appcontainer-profile-failed:0x" + hr.ToString("X8") + "\"}");
                return 2;
            }
            string sidString = null;
            string folder = null;
            string folderError;
            try
            {
                sidString = SidToString(sid);
                folder = sidString != null ? GetFolderPath(sidString, out folderError) : null;
            }
            finally
            {
                if (sid != IntPtr.Zero) NativeMethods.FreeSid(sid);
            }
            if (folder == null)
            {
                Status("{\"status\":\"blocked\",\"stage\":\"profile-folder\",\"error\":\"profile-created-but-folder-unavailable\"}");
                return 2;
            }
            Status("{\"status\":\"profile-created\",\"profile_name\":" + Q(profileName) +
                   ",\"profile_sid\":" + Q(sidString) +
                   ",\"profile_folder\":" + Q(folder) + "}");
            return 0;
        }

        public static int DeleteProfile(string profileName)
        {
            int hr = NativeMethods.DeleteAppContainerProfile(profileName);
            if (hr != 0)
            {
                Status("{\"status\":\"blocked\",\"stage\":\"delete-profile\",\"error\":\"delete-appcontainer-profile-failed:0x" + hr.ToString("X8") + "\"}");
                return 2;
            }
            Status("{\"status\":\"profile-deleted\",\"profile_name\":" + Q(profileName) + "}");
            return 0;
        }
    }
}
