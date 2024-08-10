using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static uk.JohnCook.dotnet.LTOEncryptionManager.SPTI.LTO;

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
	internal class NativeMethods
	{
		[Flags]
		public enum ACCESS_MASK : uint
		{
			DELETE = 0x00010000,
			READ_CONTROL = 0x00020000,
			WRITE_DAC = 0x00040000,
			WRITE_OWNER = 0x00080000,
			SYNCHRONIZE = 0x00100000,

			STANDARD_RIGHTS_REQUIRED = 0x000F0000,

			STANDARD_RIGHTS_READ = 0x00020000,
			STANDARD_RIGHTS_WRITE = 0x00020000,
			STANDARD_RIGHTS_EXECUTE = 0x00020000,

			STANDARD_RIGHTS_ALL = 0x001F0000,

			SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

			ACCESS_SYSTEM_SECURITY = 0x01000000,

			MAXIMUM_ALLOWED = 0x02000000,

			GENERIC_READ = 0x80000000,
			GENERIC_WRITE = 0x40000000,
			GENERIC_EXECUTE = 0x20000000,
			GENERIC_ALL = 0x10000000,

			DESKTOP_READOBJECTS = 0x00000001,
			DESKTOP_CREATEWINDOW = 0x00000002,
			DESKTOP_CREATEMENU = 0x00000004,
			DESKTOP_HOOKCONTROL = 0x00000008,
			DESKTOP_JOURNALRECORD = 0x00000010,
			DESKTOP_JOURNALPLAYBACK = 0x00000020,
			DESKTOP_ENUMERATE = 0x00000040,
			DESKTOP_WRITEOBJECTS = 0x00000080,
			DESKTOP_SWITCHDESKTOP = 0x00000100,

			WINSTA_ENUMDESKTOPS = 0x00000001,
			WINSTA_READATTRIBUTES = 0x00000002,
			WINSTA_ACCESSCLIPBOARD = 0x00000004,
			WINSTA_CREATEDESKTOP = 0x00000008,
			WINSTA_WRITEATTRIBUTES = 0x00000010,
			WINSTA_ACCESSGLOBALATOMS = 0x00000020,
			WINSTA_EXITWINDOWS = 0x00000040,
			WINSTA_ENUMERATE = 0x00000100,
			WINSTA_READSCREEN = 0x00000200,

			WINSTA_ALL_ACCESS = 0x0000037F
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public int bInheritHandle;
		}

		[DllImport("user32.dll", EntryPoint = "CreateDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
		public static extern IntPtr CreateDesktop(
				[In, MarshalAs(UnmanagedType.LPWStr)] string desktopName,
				[MarshalAs(UnmanagedType.LPWStr)] string? device, // must be null.
				[MarshalAs(UnmanagedType.LPWStr)] string? deviceMode, // must be null,
				[In, MarshalAs(UnmanagedType.U4)] int flags,  // use 0
				[In, MarshalAs(UnmanagedType.U4)] ACCESS_MASK accessMask,
				[In, Optional, MarshalAs(UnmanagedType.Struct)] ref SECURITY_ATTRIBUTES attributes);

		[DllImport("kernel32.dll")]
		public static extern void RtlZeroMemory(IntPtr dst, int length);


		[DllImport("msvcrt.dll", SetLastError = false)]
		public static extern IntPtr memcpy(IntPtr dest, IntPtr src, int count);

		[DllImport("Kernel32.dll", SetLastError = false, CharSet = CharSet.Auto)]
		public static extern bool DeviceIoControl(
			[In] in SafeFileHandle hDevice,												// [in] HANDLE
			[In] in uint IoControlCode,													// [in] DWORD
			[In, Out, Optional] ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX InBuffer,	// [in, optional] LPVOID
			[In] in uint nInBufferSize,													// [in] DWORD
			[In, Out, Optional] ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX OutBuffer,	// [out, optional] LPVOID
			[In] in uint nOutBufferSize,												// [in] DWORD
			[Out, Optional] out uint pBytesReturned,									// [out, optional] LPDWORD
			[In, Out, Optional] ref System.Threading.NativeOverlapped Overlapped);		// [in, out, optional] LPOVERLAPPED


		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "GetTapeDriveHandle", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern IntPtr GetTapeDriveHandle([In, MarshalAs(UnmanagedType.LPStr)] string devicePath);

		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "QueryPropertyForDevice", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern Windows.Win32.Foundation.BOOL QueryPropertyForDevice([In] SafeFileHandle DeviceHandle, [Out] out uint AlignmentMask, [Out] out byte SrbType, [Out] out Windows.Win32.Storage.FileSystem.STORAGE_BUS_TYPE StorageBusType, [In, Out, MarshalAs(UnmanagedType.LPStr)] StringBuilder driveSerialNumber, [In] int serialNumberBufferLength);

		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "GetScsiPassthroughWithBuffersEx", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern IntPtr GetScsiPassthroughWithBuffersEx();

		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "ResetSrbIn", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern uint ResetSrbIn(IntPtr psptwb_ex, byte opCode);

		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "SendSrb", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern bool SendSrb(SafeFileHandle tapeHandle, IntPtr psptwb_ex, uint length, out uint returned);

		//[DllImport(@"H:\source\repos\LTO-Encryption-SPTI\x64\Debug\LTO-Encryption-SPTI-Library.dll", EntryPoint = "ParseDeviceIdentifiers", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
		//public static extern void ParseDeviceIdentifiers(IntPtr deviceIdentifiers, out short pLogicalUnitIdentifierLength, out string ppLogicalUnitIdentifier);
	}
}
