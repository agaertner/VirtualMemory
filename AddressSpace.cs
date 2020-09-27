using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace VirtualMemory
{
    /// <summary>
    /// Wrapper for kernel32 read/write virtual process memory methods.
    /// </summary>
    public class AddressSpace
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            uint dwSize, uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            uint nSize, uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        public string ProcessName { get; set; }

        /// <summary>
        /// The base address of the main module of the main process.
        /// </summary>
        public long GetBaseAddress
        {
            get
            {
                _baseAddress = (IntPtr) 0;
                _processModule = _mainProcess[0].MainModule;
                _baseAddress = _processModule?.BaseAddress ?? IntPtr.Zero;
                return (long) _baseAddress;
            }
        }

        public AddressSpace() { }

        public AddressSpace(string pProcessName)
        {
            ProcessName = pProcessName;
        }

        /// <summary>
        /// Gets the process matching the name in 'ProcessName' and opens it.
        /// </summary>
        /// <exception cref="InvalidOperationException">If process name is not defined.</exception>
        /// <exception cref="ProcessNotFoundException">If no running process matches the defined name.</exception>
        public void Initialize()
        {
            if (ProcessName == null)
                throw new InvalidOperationException("A process name was not defined.");

            _mainProcess = Process.GetProcessesByName(ProcessName);
            if (_mainProcess.Length == 0)
                throw new ProcessNotFoundException($"The process '{ProcessName}' has not been found.");

            _processHandle = OpenProcess(2035711U, false, _mainProcess[0].Id);
            if (_processHandle == IntPtr.Zero)
                throw new ProcessNotFoundException($"The process '{ProcessName}' has not been found.");
        }

        private static readonly Regex GetHexadecimal = new Regex("(0x)?[a-fA-F0-9]+", RegexOptions.Multiline | RegexOptions.Compiled);

        /// <summary>
        /// Resolves a multi-level 64bit pointer address.
        /// </summary>
        /// <param name="address">Separated (in any way) list of base address and pointers.<para/>
        /// Example: $"{BaseAddress} + 0x01639068 + 0x508 + 0x38 + 0x30 + 0x338 + 0xDC"<para/>
        /// Note: "0x" is not needed. RegEx is used to match any hexadecimals.</param>
        /// <returns>The actual and final address that is pointed to.</returns>
        public long ResolveInt64FromString(string address)
        {
            var offsets = GetHexadecimal.Matches(address).Cast<Match>().Select(m => m.Value).ToArray();
            long current = Convert.ToInt64(offsets[0]);
            for (int i = 1; i < offsets.Length - 1; i++)
                current = ReadInt64((IntPtr) current + Convert.ToInt32(offsets[i], 16));
            return current + Convert.ToInt32(offsets[offsets.Length - 1], 16);
        }
        /// <summary>
        /// Resolves a multi-level 32bit pointer address.
        /// </summary>
        /// <param name="address">Separated (in any way) list of address and pointers.<para/>
        /// Example: $"{BaseAddress} + 0x01639068 + 0x508 + 0x38 + 0x30 + 0x338 + 0xDC"<para/>
        /// Note: "0x" is not needed. RegEx is used to match any hexadecimals.</param>
        /// <returns>The actual and final address that is pointed to.</returns>
        public int ResolveInt32FromString(string address)
        {
            var offsets = GetHexadecimal.Matches(address).Cast<Match>().Select(m => m.Value).ToArray();
            int current = Convert.ToInt32(offsets[0]);
            for (int i = 1; i < offsets.Length - 1; i++)
                current = ReadInt32((IntPtr) current + Convert.ToInt32(offsets[i], 16));
            return current + Convert.ToInt32(offsets[offsets.Length - 1], 16);
        }

        public byte[] ReadByteArray(IntPtr pOffset, uint pSize)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            byte[] result;
            try
            {
                VirtualProtectEx(_processHandle, pOffset, (UIntPtr) pSize, 4U, out var flNewProtect);
                byte[] array = new byte[pSize];
                ReadProcessMemory(_processHandle, pOffset, array, pSize, 0U);
                VirtualProtectEx(_processHandle, pOffset, (UIntPtr) pSize, flNewProtect, out flNewProtect);
                result = array;
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadByteArray" + ex);
                }

                result = new byte[1];
            }

            return result;
        }

        public string ReadStringUnicode(IntPtr pOffset, uint pSize)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            string result;
            try
            {
                result = Encoding.Unicode.GetString(ReadByteArray(pOffset, pSize), 0, (int) pSize);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadStringUnicode" + ex);
                }

                result = "";
            }

            return result;
        }

        public string ReadStringASCII(IntPtr pOffset, uint pSize)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            string result;
            try
            {
                result = Encoding.ASCII.GetString(ReadByteArray(pOffset, pSize), 0, (int) pSize);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadStringASCII" + ex);
                }

                result = "";
            }

            return result;
        }

        public char ReadChar(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            char result;
            try
            {
                result = BitConverter.ToChar(ReadByteArray(pOffset, 1U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadChar" + ex);
                }

                result = ' ';
            }

            return result;
        }

        public bool ReadBoolean(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = BitConverter.ToBoolean(ReadByteArray(pOffset, 1U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadByte" + ex);
                }

                result = false;
            }

            return result;
        }

        public byte ReadByte(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            byte result;
            try
            {
                result = ReadByteArray(pOffset, 1U)[0];
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadByte" + ex);
                }

                result = 0;
            }

            return result;
        }

        public short ReadInt16(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            short result;
            try
            {
                result = BitConverter.ToInt16(ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadInt16" + ex);
                }

                result = 0;
            }

            return result;
        }

        public short ReadShort(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            short result;
            try
            {
                result = BitConverter.ToInt16(ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadInt16" + ex);
                }

                result = 0;
            }

            return result;
        }

        public int ReadInt32(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            int result;
            try
            {
                result = BitConverter.ToInt32(ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadInt32" + ex);
                }

                result = 0;
            }

            return result;
        }

        public int ReadInteger(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            int result;
            try
            {
                result = BitConverter.ToInt32(ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadInteger" + ex);
                }

                result = 0;
            }

            return result;
        }

        public long ReadInt64(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            long result;
            try
            {
                result = BitConverter.ToInt64(ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadInt64" + ex);
                }

                result = 0L;
            }

            return result;
        }

        public long ReadLong(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            long result;
            try
            {
                result = BitConverter.ToInt64(ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadLong" + ex);
                }

                result = 0L;
            }

            return result;
        }

        public ushort ReadUInt16(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            ushort result;
            try
            {
                result = BitConverter.ToUInt16(ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadUInt16" + ex);
                }

                result = 0;
            }

            return result;
        }

        public ushort ReadUShort(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            ushort result;
            try
            {
                result = BitConverter.ToUInt16(ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadUShort" + ex);
                }

                result = 0;
            }

            return result;
        }

        public uint ReadUInt32(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            uint result;
            try
            {
                result = BitConverter.ToUInt32(ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadUInt32" + ex);
                }

                result = 0U;
            }

            return result;
        }

        public uint ReadUInteger(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            uint result;
            try
            {
                result = BitConverter.ToUInt32(ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadUInteger" + ex);
                }

                result = 0U;
            }

            return result;
        }

        public ulong ReadUInt64(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            ulong result;
            try
            {
                result = BitConverter.ToUInt64(ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadUInt64" + ex);
                }

                result = 0UL;
            }

            return result;
        }

        public long ReadULong(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            long result;
            try
            {
                result = (long) BitConverter.ToUInt64(ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadULong" + ex);
                }

                result = 0L;
            }

            return result;
        }

        public float ReadFloat(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            float result;
            try
            {
                result = BitConverter.ToSingle(ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadFloat" + ex);
                }

                result = 0f;
            }

            return result;
        }

        public double ReadDouble(IntPtr pOffset)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            double result;
            try
            {
                result = BitConverter.ToDouble(ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: ReadDouble" + ex);
                }

                result = 0.0;
            }

            return result;
        }

        public bool WriteByteArray(IntPtr pOffset, byte[] pBytes)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                uint flNewProtect;
                VirtualProtectEx(_processHandle, pOffset, (UIntPtr) ((ulong) pBytes.Length), 4U,
                    out flNewProtect);
                bool flag = WriteProcessMemory(_processHandle, pOffset, pBytes, (uint) pBytes.Length, 0U);
                VirtualProtectEx(_processHandle, pOffset, (UIntPtr) ((ulong) pBytes.Length),
                    flNewProtect, out flNewProtect);
                result = flag;
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteByteArray" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteStringUnicode(IntPtr pOffset, string pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, Encoding.Unicode.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteStringUnicode" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteStringASCII(IntPtr pOffset, string pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, Encoding.ASCII.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteStringASCII" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteBoolean(IntPtr pOffset, bool pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteBoolean" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteChar(IntPtr pOffset, char pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteChar" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteByte(IntPtr pOffset, byte pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteByte" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt16(IntPtr pOffset, short pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteInt16" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteShort(IntPtr pOffset, short pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteShort" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt32(IntPtr pOffset, int pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteInt32" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteInteger(IntPtr pOffset, int pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteInt" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt64(IntPtr pOffset, long pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteInt64" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteLong(IntPtr pOffset, long pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteLong" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt16(IntPtr pOffset, ushort pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteUInt16" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteUShort(IntPtr pOffset, ushort pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteShort" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt32(IntPtr pOffset, uint pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteUInt32" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInteger(IntPtr pOffset, uint pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteUInt" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt64(IntPtr pOffset, ulong pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteUInt64" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteULong(IntPtr pOffset, ulong pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteULong" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteFloat(IntPtr pOffset, float pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteFloat" + ex);
                }

                result = false;
            }

            return result;
        }

        public bool WriteDouble(IntPtr pOffset, double pData)
        {
            if (_processHandle == IntPtr.Zero)
            {
                Initialize();
            }

            bool result;
            try
            {
                result = WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (DebugMode)
                {
                    Console.WriteLine("Error: WriteDouble" + ex);
                }

                result = false;
            }

            return result;
        }
        public static bool DebugMode;

        private IntPtr _baseAddress;

        private ProcessModule _processModule;

        private Process[] _mainProcess;

        private IntPtr _processHandle;

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 2035711U,
            Terminate = 1U,
            CreateThread = 2U,
            VMOperation = 8U,
            VMRead = 16U,
            VMWrite = 32U,
            DupHandle = 64U,
            SetInformation = 512U,
            QueryInformation = 1024U,
            Synchronize = 1048576U
        }

        private enum VirtualMemoryProtection : uint
        {
            PAGE_NOACCESS = 1U,
            PAGE_READONLY,
            PAGE_READWRITE = 4U,
            PAGE_WRITECOPY = 8U,
            PAGE_EXECUTE = 16U,
            PAGE_EXECUTE_READ = 32U,
            PAGE_EXECUTE_READWRITE = 64U,
            PAGE_EXECUTE_WRITECOPY = 128U,
            PAGE_GUARD = 256U,
            PAGE_NOCACHE = 512U,
            PROCESS_ALL_ACCESS = 2035711U
        }
    }

    #region Exceptions
    public class ProcessNotFoundException : Exception
    {
        public ProcessNotFoundException(string message) : base(message)
        {
        }
        public ProcessNotFoundException(string message, Exception inner) : base(message, inner)
        {
        }
    }
    #endregion
}
