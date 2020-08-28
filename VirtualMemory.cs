using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace VirtualMemory
{
    public class VirtualMemory
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

        public string processName { get; set; }

        /// <summary>
        /// The base address of the main module of the main process.
        /// </summary>
        public long getBaseAddress
        {
            get
            {
                this.baseAddress = (IntPtr) 0;
                this.processModule = this.mainProcess[0].MainModule;
                this.baseAddress = this.processModule.BaseAddress;
                return (long) this.baseAddress;
            }
        }

        public VirtualMemory() { }

        public VirtualMemory(string pProcessName)
        {
            this.processName = pProcessName;
        }

        /// <summary>
        /// Checks if the process exists and that it can be opened.
        /// </summary>
        /// <returns>TRUE if process exists. Otherwise FALSE</returns>
        public bool CheckProcess()
        {
            if (this.processName == null)
            {
                MessageBox.Show("Programmer, define process name first!");
                return false;
            }

            this.mainProcess = Process.GetProcessesByName(this.processName);
            if (this.mainProcess.Length == 0)
            {
                this.ErrorProcessNotFound(this.processName);
                return false;
            }

            this.processHandle = VirtualMemory.OpenProcess(2035711U, false, this.mainProcess[0].Id);
            if (this.processHandle == IntPtr.Zero)
            {
                this.ErrorProcessNotFound(this.processName);
                return false;
            }

            return true;
        }

        private static readonly Regex GET_HEXADECIMAL = new Regex($"(0x)?[a-fA-F0-9]+", RegexOptions.Multiline | RegexOptions.Compiled);

        /// <summary>
        /// Resolves a multi-level 64bit pointer address.
        /// </summary>
        /// <param name="address">Separated list of base address and pointers<para/>
        /// (ex.: $"{BaseAddress}+0x01639068+0x508+0x38+0x30+0x338+0xDC").<para/>
        /// Note: "0x" is not needed. RegEx is used to match any hexadecimals.</param>
        /// <returns>The address that is pointed to.</returns>
        public long ResolveInt64FromString(string address)
        {
            var offsets = GET_HEXADECIMAL.Matches(address).Cast<Match>().Select(m => m.Value).ToArray();
            long current = Convert.ToInt64(offsets[0]);
            for (int i = 1; i < offsets.Length - 1; i++)
                current = this.ReadInt64((IntPtr) current + Convert.ToInt32(offsets[i], 16));
            return current + Convert.ToInt32(offsets[offsets.Length - 1], 16);
        }
        /// <summary>
        /// Resolves a multi-level 32bit pointer address.
        /// </summary>
        /// <param name="address">Separated list of address and pointers<para/>
        /// Example: $"{BaseAddress}+0x01639068+0x508+0x38+0x30+0x338+0xDC").<para/>
        /// Note: "0x" is not needed. RegEx is used to match any hexadecimals.</param>
        /// <returns>The address that is pointed to.</returns>
        public int ResolveInt32FromString(string address)
        {
            var offsets = GET_HEXADECIMAL.Matches(address).Cast<Match>().Select(m => m.Value).ToArray();
            int current = Convert.ToInt32(offsets[0]);
            for (int i = 1; i < offsets.Length - 1; i++)
                current = this.ReadInt32((IntPtr) current + Convert.ToInt32(offsets[i], 16));
            return current + Convert.ToInt32(offsets[offsets.Length - 1], 16);
        }

        public byte[] ReadByteArray(IntPtr pOffset, uint pSize)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            byte[] result;
            try
            {
                uint flNewProtect;
                VirtualMemory.VirtualProtectEx(this.processHandle, pOffset, (UIntPtr) pSize, 4U, out flNewProtect);
                byte[] array = new byte[pSize];
                VirtualMemory.ReadProcessMemory(this.processHandle, pOffset, array, pSize, 0U);
                VirtualMemory.VirtualProtectEx(this.processHandle, pOffset, (UIntPtr) pSize, flNewProtect, out flNewProtect);
                result = array;
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadByteArray" + ex.ToString());
                }

                result = new byte[1];
            }

            return result;
        }

        public string ReadStringUnicode(IntPtr pOffset, uint pSize)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            string result;
            try
            {
                result = Encoding.Unicode.GetString(this.ReadByteArray(pOffset, pSize), 0, (int) pSize);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadStringUnicode" + ex.ToString());
                }

                result = "";
            }

            return result;
        }

        public string ReadStringASCII(IntPtr pOffset, uint pSize)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            string result;
            try
            {
                result = Encoding.ASCII.GetString(this.ReadByteArray(pOffset, pSize), 0, (int) pSize);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadStringASCII" + ex.ToString());
                }

                result = "";
            }

            return result;
        }

        public char ReadChar(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            char result;
            try
            {
                result = BitConverter.ToChar(this.ReadByteArray(pOffset, 1U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadChar" + ex.ToString());
                }

                result = ' ';
            }

            return result;
        }

        public bool ReadBoolean(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = BitConverter.ToBoolean(this.ReadByteArray(pOffset, 1U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadByte" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public byte ReadByte(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            byte result;
            try
            {
                result = this.ReadByteArray(pOffset, 1U)[0];
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadByte" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public short ReadInt16(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            short result;
            try
            {
                result = BitConverter.ToInt16(this.ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadInt16" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public short ReadShort(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            short result;
            try
            {
                result = BitConverter.ToInt16(this.ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadInt16" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public int ReadInt32(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            int result;
            try
            {
                result = BitConverter.ToInt32(this.ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadInt32" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public int ReadInteger(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            int result;
            try
            {
                result = BitConverter.ToInt32(this.ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadInteger" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public long ReadInt64(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            long result;
            try
            {
                result = BitConverter.ToInt64(this.ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadInt64" + ex.ToString());
                }

                result = 0L;
            }

            return result;
        }

        public long ReadLong(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            long result;
            try
            {
                result = BitConverter.ToInt64(this.ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadLong" + ex.ToString());
                }

                result = 0L;
            }

            return result;
        }

        public ushort ReadUInt16(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            ushort result;
            try
            {
                result = BitConverter.ToUInt16(this.ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadUInt16" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public ushort ReadUShort(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            ushort result;
            try
            {
                result = BitConverter.ToUInt16(this.ReadByteArray(pOffset, 2U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadUShort" + ex.ToString());
                }

                result = 0;
            }

            return result;
        }

        public uint ReadUInt32(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            uint result;
            try
            {
                result = BitConverter.ToUInt32(this.ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadUInt32" + ex.ToString());
                }

                result = 0U;
            }

            return result;
        }

        public uint ReadUInteger(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            uint result;
            try
            {
                result = BitConverter.ToUInt32(this.ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadUInteger" + ex.ToString());
                }

                result = 0U;
            }

            return result;
        }

        public ulong ReadUInt64(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            ulong result;
            try
            {
                result = BitConverter.ToUInt64(this.ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadUInt64" + ex.ToString());
                }

                result = 0UL;
            }

            return result;
        }

        public long ReadULong(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            long result;
            try
            {
                result = (long) BitConverter.ToUInt64(this.ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadULong" + ex.ToString());
                }

                result = 0L;
            }

            return result;
        }

        public float ReadFloat(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            float result;
            try
            {
                result = BitConverter.ToSingle(this.ReadByteArray(pOffset, 4U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadFloat" + ex.ToString());
                }

                result = 0f;
            }

            return result;
        }

        public double ReadDouble(IntPtr pOffset)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            double result;
            try
            {
                result = BitConverter.ToDouble(this.ReadByteArray(pOffset, 8U), 0);
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: ReadDouble" + ex.ToString());
                }

                result = 0.0;
            }

            return result;
        }

        public bool WriteByteArray(IntPtr pOffset, byte[] pBytes)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                uint flNewProtect;
                VirtualMemory.VirtualProtectEx(this.processHandle, pOffset, (UIntPtr) ((ulong) ((long) pBytes.Length)), 4U,
                    out flNewProtect);
                bool flag = VirtualMemory.WriteProcessMemory(this.processHandle, pOffset, pBytes, (uint) pBytes.Length, 0U);
                VirtualMemory.VirtualProtectEx(this.processHandle, pOffset, (UIntPtr) ((ulong) ((long) pBytes.Length)),
                    flNewProtect, out flNewProtect);
                result = flag;
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteByteArray" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteStringUnicode(IntPtr pOffset, string pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, Encoding.Unicode.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteStringUnicode" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteStringASCII(IntPtr pOffset, string pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, Encoding.ASCII.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteStringASCII" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteBoolean(IntPtr pOffset, bool pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteBoolean" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteChar(IntPtr pOffset, char pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteChar" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteByte(IntPtr pOffset, byte pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes((short) pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteByte" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt16(IntPtr pOffset, short pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteInt16" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteShort(IntPtr pOffset, short pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteShort" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt32(IntPtr pOffset, int pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteInt32" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteInteger(IntPtr pOffset, int pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteInt" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteInt64(IntPtr pOffset, long pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteInt64" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteLong(IntPtr pOffset, long pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteLong" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt16(IntPtr pOffset, ushort pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteUInt16" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteUShort(IntPtr pOffset, ushort pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteShort" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt32(IntPtr pOffset, uint pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteUInt32" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInteger(IntPtr pOffset, uint pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteUInt" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteUInt64(IntPtr pOffset, ulong pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteUInt64" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteULong(IntPtr pOffset, ulong pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteULong" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteFloat(IntPtr pOffset, float pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteFloat" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        public bool WriteDouble(IntPtr pOffset, double pData)
        {
            if (this.processHandle == IntPtr.Zero)
            {
                this.CheckProcess();
            }

            bool result;
            try
            {
                result = this.WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception ex)
            {
                if (VirtualMemory.debugMode)
                {
                    Console.WriteLine("Error: WriteDouble" + ex.ToString());
                }

                result = false;
            }

            return result;
        }

        private void ErrorProcessNotFound(string pProcessName)
        {
            MessageBox.Show(this.processName + " is not running or has not been found. Please check and try again",
                "Process Not Found", MessageBoxButtons.OK, MessageBoxIcon.Hand);
        }

        public static bool debugMode;

        private IntPtr baseAddress;

        private ProcessModule processModule;

        private Process[] mainProcess;

        private IntPtr processHandle;

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
}
