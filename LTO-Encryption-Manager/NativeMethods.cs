using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;
using static uk.JohnCook.dotnet.LTOEncryptionManager.SPTI.LTO;

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
	internal sealed partial class NativeMethods
	{
		[Flags]
		public enum ACCESS_MASK : uint
		{
#pragma warning disable CA1069 // Enums values should not be duplicated
			DELETE = FILE_ACCESS_RIGHTS.DELETE,
			READ_CONTROL = FILE_ACCESS_RIGHTS.READ_CONTROL,
			WRITE_DAC = FILE_ACCESS_RIGHTS.WRITE_DAC,
			WRITE_OWNER = FILE_ACCESS_RIGHTS.WRITE_OWNER,
			SYNCHRONIZE = FILE_ACCESS_RIGHTS.SYNCHRONIZE,

			STANDARD_RIGHTS_REQUIRED = FILE_ACCESS_RIGHTS.STANDARD_RIGHTS_REQUIRED,

			STANDARD_RIGHTS_READ = FILE_ACCESS_RIGHTS.STANDARD_RIGHTS_READ,
			STANDARD_RIGHTS_WRITE = FILE_ACCESS_RIGHTS.STANDARD_RIGHTS_WRITE,
			STANDARD_RIGHTS_EXECUTE = FILE_ACCESS_RIGHTS.STANDARD_RIGHTS_EXECUTE,

			STANDARD_RIGHTS_ALL = FILE_ACCESS_RIGHTS.STANDARD_RIGHTS_ALL,

			SPECIFIC_RIGHTS_ALL = FILE_ACCESS_RIGHTS.SPECIFIC_RIGHTS_ALL,

			ACCESS_SYSTEM_SECURITY = 0x01000000,

			MAXIMUM_ALLOWED = 0x02000000,

			GENERIC_READ = GENERIC_ACCESS_RIGHTS.GENERIC_READ,
			GENERIC_WRITE = GENERIC_ACCESS_RIGHTS.GENERIC_WRITE,
			GENERIC_EXECUTE = GENERIC_ACCESS_RIGHTS.GENERIC_EXECUTE,
			GENERIC_ALL = GENERIC_ACCESS_RIGHTS.GENERIC_ALL,

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
#pragma warning restore CA1069 // Enums values should not be duplicated
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public int bInheritHandle;
		}

		[DllImport("user32.dll", EntryPoint = "CreateDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		public static extern IntPtr CreateDesktop(
				[In, MarshalAs(UnmanagedType.LPWStr)] string desktopName,
				[MarshalAs(UnmanagedType.LPWStr)] string? device, // must be null.
				[MarshalAs(UnmanagedType.LPWStr)] string? deviceMode, // must be null,
				[In, MarshalAs(UnmanagedType.U4)] int flags,  // use 0
				[In, MarshalAs(UnmanagedType.U4)] ACCESS_MASK accessMask,
				[In, Optional, MarshalAs(UnmanagedType.Struct)] ref SECURITY_ATTRIBUTES attributes);

		[LibraryImport("kernel32.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		public static partial void RtlZeroMemory(IntPtr dst, int length);


		[LibraryImport("msvcrt.dll", SetLastError = false)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		public static partial IntPtr memcpy(IntPtr dest, IntPtr src, int count);

		[DllImport("kernel32.dll", SetLastError = false, CharSet = CharSet.Auto)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		public static extern bool DeviceIoControl(
			[In] in SafeFileHandle hDevice,												// [in] HANDLE
			[In] in uint IoControlCode,													// [in] DWORD
			[In, Out, Optional] ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX InBuffer,	// [in, optional] LPVOID
			[In] in uint nInBufferSize,													// [in] DWORD
			[In, Out, Optional] ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX OutBuffer,	// [out, optional] LPVOID
			[In] in uint nOutBufferSize,												// [in] DWORD
			[Out, Optional] out uint pBytesReturned,									// [out, optional] LPDWORD
			[In, Out, Optional] ref System.Threading.NativeOverlapped Overlapped);		// [in, out, optional] LPOVERLAPPED

	}
}
