using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SPTI
{
	public partial class LTO
	{

		/// <summary>
		/// "Define 8 bit bus, target and LUN address scheme" --<c>STOR_ADDR_BTL8</c> (from Win32 <c>scsi.h</c>)
		/// </summary>
		/// <remarks>
		/// <para><b>Call <see cref="Init"/> after instantiation to initialise the structure with <c>STOR_ADDR_BTL8</c> values.</b></para>
		/// <para>In <c>scsi.h</c>, <c>STOR_ADDR_BTL8</c> is a type of <c>STOR_ADDRESS_ALIGN</c>, with the only currently existing type of <c>STOR_ADDRESS_ALIGN</c> being <c>0x1</c>: <c>STOR_ADDR_BTL8</c>.</para>
		/// <para>On 64-bit Windows and M_Alpha, <c>#define STOR_ADDRESS_ALIGN DECLSPEC_ALIGN(8)</c> - "define alignment requirements for variable length components in extended SRB".</para>
		/// <para>"For Win64, need to ensure all variable length components are 8 bytes align so the pointer fields within the variable length components are 8 bytes align."</para>
		/// </remarks>
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct STOR_ADDR_BTL8
		{
			[MarshalAs(UnmanagedType.U2)]
			public ushort Type;
			[MarshalAs(UnmanagedType.U2)]
			public ushort Port;
			[MarshalAs(UnmanagedType.U4)]
			public uint AddressLength;
			[MarshalAs(UnmanagedType.U1)]
			public byte Path;
			[MarshalAs(UnmanagedType.U1)]
			public byte Target;
			[MarshalAs(UnmanagedType.U1)]
			public byte Lun;
			[MarshalAs(UnmanagedType.U1)]
			public byte Reserved;
			[MarshalAs(UnmanagedType.U4)]
			public uint Filler; // Ensures structure length is a multiple of 8 bytes

			public void Init()
			{
				Type = Constants.STOR_ADDRESS_TYPE_BTL8;
				Port = default;
				AddressLength = Constants.STOR_ADDR_BTL8_ADDRESS_LENGTH;
				Path = default;
				Target = default;
				Lun = default;
				Reserved = default;
				Filler = default;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
		internal struct NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX
		{
			/// <summary>
			/// A <see cref="Windows.Win32.Storage.IscsiDisc.SCSI_PASS_THROUGH_EX"/> structure, and the first 8 bytes of the CDB
			/// </summary>
			/// <remarks>
			/// <para><b>Call <see cref="Init"/> after instantiation to initialise the structure.</b></para>
			/// <para>Length (including .Cdb[0]): 49 bytes (32-bit) or 57 bytes (64-bit)</para>
			/// <para>Length (Pack = 8): 56 bytes (32-bit) or 64 bytes (64-bit)</para>
			/// <para>Total structure length: 56 bytes (32-bit) or 64 bytes (64-bit)</para>
			/// </remarks>
			internal Windows.Win32.Storage.IscsiDisc.SCSI_PASS_THROUGH_EX spt;

			/// <summary>
			/// The remaining bytes of the CDB (ucCdbBuf[0] = spt.Cdb[9])
			/// </summary>
			/// <remarks>
			/// <para><b>Use <see cref="SetCbdValue(int, byte)"/> instead of using this array.</b></para>
			/// <para>Initialised as part of <see cref="Init"/>.</para>
			/// <para>Length: 32 bytes</para>
			/// <para>Total structure length: 88 bytes (32-bit) or 96 bytes (64-bit)</para>
			/// </remarks>
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.SPT_CDB_LENGTH)]
			internal byte[] CdbExtendedBuffer;

			/// <summary>
			/// Filler bytes for aligning the end of <see cref="StorAddress"/> on an 8-byte boundary
			/// </summary>
			/// <remarks>
			/// <para>In C, this is a <c>ULONG</c> (a <see cref="uint"/>)</para>
			/// <para>Probably unnecessary with <c><see cref="StructLayoutAttribute.Pack"/> = 8</c></para>
			/// <para>Length: 8 bytes</para>
			/// <para>Total structure length: 96 bytes (32-bit) or 104 bytes (64-bit)</para>
			/// </remarks>
			public ulong Filler;

			/// <summary>
			/// A <see cref="STOR_ADDR_BTL8"/>
			/// </summary>
			/// <remarks>
			/// <para>Length: 16 bytes</para>
			/// <para>Total structure length: 112 bytes (32-bit) or 120 bytes (64-bit)</para>
			/// </remarks>
			public STOR_ADDR_BTL8 StorAddress;

			//public uint Filler2;

			/// <summary>
			/// Buffer for sense data
			/// </summary>
			/// <remarks>
			/// <para>Length: 32 bytes</para>
			/// <para>Total structure length: 144 bytes (32-bit) or 152 bytes (64-bit)</para>
			/// </remarks>
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.SPT_SENSE_LENGTH)]
			public byte[] ucSenseBuf;

			/// <summary>
			/// Buffer for input/output data
			/// </summary>
			/// <remarks>
			/// <para>Length: 4096 bytes</para>
			/// <para>Total structure length: 4240 bytes (32-bit) or 4248 bytes (64-bit)</para>
			/// </remarks>
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.SPTWB_DATA_LENGTH)]
			public byte[] ucDataBuf;

			public void Init()
			{
				spt = new();
				StorAddress = new();
				StorAddress.Init();
				CdbExtendedBuffer = new byte[Constants.SPT_CDB_LENGTH];
				Array.Fill<byte>(CdbExtendedBuffer, 0x77);
				ucSenseBuf = new byte[Constants.SPT_SENSE_LENGTH];
				ucDataBuf = new byte[Constants.SPTWB_DATA_LENGTH];
			}

			public void Clear()
			{
				spt = new();
				StorAddress = new();
				StorAddress.Init();
				Array.Clear(CdbExtendedBuffer, 0, CdbExtendedBuffer.Length);
				Array.Fill<byte>(CdbExtendedBuffer, 0x00);
				Array.Clear(ucSenseBuf, 0, ucSenseBuf.Length);
				Array.Clear(ucDataBuf, 0, ucDataBuf.Length);
			}

			public void SetCbdValue(int arrayPosition, byte value)
			{
				if (arrayPosition < 8)
				{
					Windows.Win32.InlineArrayIndexerExtensions.ItemRef(ref spt.Cdb, arrayPosition) = value;
				}
				else if (arrayPosition < CdbExtendedBuffer.Length + 8)
				{
					CdbExtendedBuffer[arrayPosition - 8] = value;
				}
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		internal struct VPD_IDENTIFICATION_DESCRIPTOR
		{
			public byte Byte1;
			public byte Byte2;
			public byte Byte3;
			public byte IdentifierLength;
			public byte[] Identifier;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		internal struct VPD_IDENTIFICATION_PAGE
		{
			public byte Byte1; // Bit field
			public byte PageCode;
			public byte Reserved;
			public byte PageLength;
			public List<VPD_IDENTIFICATION_DESCRIPTOR> Descriptors;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY
		{
			public ushort PageCode; /* Network Byte Order */
			public ushort PageLength; /* Network Byte Order */
			public uint PublicKeyType; /* Network Byte Order */
			public uint PublicKeyFormat; /* Network Byte Order */
			public ushort PublicKeyLength; /* Network Byte Order */
			public byte[] PublicKey;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct WRAPPED_KEY_DESCRIPTOR
		{
			public byte Type;
			public byte Reserved1;
			public ushort Length; /* Network Byte Order */
			public byte[] Descriptor;
		}

		public static byte GetCdbLength(byte opCode)
		{
			byte groupCode = (byte)((opCode & 0xE0) >> 5);
			return groupCode switch
			{
				0 or 3 => Constants.CDB6GENERIC_LENGTH,
				1 or 2 => Constants.CDB10GENERIC_LENGTH,
				5 => Constants.CDB12GENERIC_LENGTH,
				// 16 byte commands
				4 => Constants.CDB16GENERIC_LENGTH,
				// vendor-unique commands
				_ => 0
			};
		}



		internal static bool TrySendSrb(TapeDrive tapeDrive, ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, uint length, out uint returnedData, out int hresult)
		{
			returnedData = 0;
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				hresult = unchecked((int)0x80070006); // E_HANDLE; Handle that is not valid
				return false;
			}
			//uint dataBufferOffset = (uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucDataBuf)) + 256;
			uint dataBufferOffset = (uint)length;
			byte[] buffer = new byte[dataBufferOffset];
			IntPtr bufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>());
			Marshal.StructureToPtr(sptwb_ex, bufferPtr, true);
			Marshal.Copy(bufferPtr, buffer, 0, buffer.Length);
			Marshal.FreeHGlobal(bufferPtr);
			//Trace.WriteLine(Convert.ToHexString(buffer, 0, (int)dataBufferOffset));
			try
			{
				bool status = false;
				IntPtr psptwb_ex = Marshal.AllocHGlobal(Marshal.SizeOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>());
				Marshal.StructureToPtr(sptwb_ex, psptwb_ex, true);
				Windows.Win32.System.IO.OVERLAPPED overlapped = new();
				uint outputLength = 0;
				unsafe
				{
					Windows.Win32.Foundation.BOOL ok = Windows.Win32.PInvoke.DeviceIoControl(tapeDrive.Handle,
						Windows.Win32.PInvoke.IOCTL_SCSI_PASS_THROUGH_EX,
						(void*)psptwb_ex,
						(uint)Marshal.SizeOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(),
						(void*)psptwb_ex,
						length,
						&outputLength,
						&overlapped);
					status = ok == Constants.TRUE;
				}
				returnedData = outputLength;
				sptwb_ex = Marshal.PtrToStructure<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(psptwb_ex);
				if (!status)
				{
					hresult = Marshal.GetHRForLastWin32Error();
					return false;
				}
				else
				{
					hresult = unchecked(0x00000000); // S_OK
					return true;
				}
			}
			catch (Exception ex)
			{
				hresult = Marshal.GetHRForException(ex);
				return false;
			}
		}

		internal static bool WaitForSenseChange(TapeDrive tapeDrive, ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return false;
			}
			bool status;
			uint length;
			//printf("Waiting for sense change...");
			byte senseKey = (byte)(sptwb_ex.ucSenseBuf[2] & 0x0F);

			byte retriesRemaining = 10;
			while (senseKey == 0 && retriesRemaining > 0)
			{
				length = ResetSrbIn(ref sptwb_ex, Constants.SCSIOP_REQUEST_SENSE);

				uint returnedData = 0;

				status = TrySendSrb(tapeDrive, ref sptwb_ex, length, out returnedData, out int hresult);

				senseKey = (byte)(sptwb_ex.ucSenseBuf[2] & 0x0F);
				retriesRemaining--;
			}
			//printf("\n");
			if (senseKey != 0)
			{
				//PrintSenseInfoEx(psptwb_ex);
				//Trace.WriteLine($"SenseInfo: {Convert.ToHexString(sptwb_ex.ucSenseBuf)}");
				return true;
			}
			else
			{
				//printf("Giving up.\n");
				return false;
			}
		}

		private static uint ResetSrbIn(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, byte opCode)
		{
			byte cdbLength = GetCdbLength(opCode);
			if (cdbLength == 0) { return cdbLength; }

			sptwb_ex.Clear();

			sptwb_ex.spt.Version = 0;
			sptwb_ex.spt.Length = (uint)Marshal.SizeOf(typeof(Windows.Win32.Storage.IscsiDisc.SCSI_PASS_THROUGH_EX));
			sptwb_ex.spt.ScsiStatus = 0;
			sptwb_ex.spt.CdbLength = cdbLength;
			sptwb_ex.spt.StorAddressLength = (uint)Marshal.SizeOf<STOR_ADDR_BTL8>();
			sptwb_ex.spt.SenseInfoLength = Constants.SPT_SENSE_LENGTH;
			sptwb_ex.spt.DataOutTransferLength = 0;
			sptwb_ex.spt.DataInTransferLength = 4 << 8;
			sptwb_ex.spt.DataDirection = Constants.SCSI_IOCTL_DATA_IN;
			sptwb_ex.spt.TimeOutValue = 2;
			sptwb_ex.StorAddress.Init();
			sptwb_ex.spt.StorAddressOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.StorAddress));
			sptwb_ex.spt.SenseInfoOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucSenseBuf));
			sptwb_ex.spt.DataOutBufferOffset = 0;
			sptwb_ex.spt.DataInBufferOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucDataBuf));
			switch (opCode)
			{
				case Constants.SCSIOP_INQUIRY:
					sptwb_ex.SetCbdValue(0, opCode);
					sptwb_ex.SetCbdValue(3, (Constants.SPTWB_DATA_LENGTH >> 8) & 0xFF);
					sptwb_ex.SetCbdValue(4, Constants.SPTWB_DATA_LENGTH & 0xFF);
					break;
				case Constants.SCSIOP_SECURITY_PROTOCOL_IN:
					sptwb_ex.SetCbdValue(0, opCode);
					sptwb_ex.SetCbdValue(6, (Constants.SPTWB_DATA_LENGTH >> 24) & 0xFF);
					sptwb_ex.SetCbdValue(7, (Constants.SPTWB_DATA_LENGTH >> 16) & 0xFF);
					sptwb_ex.SetCbdValue(8, (Constants.SPTWB_DATA_LENGTH >> 8) & 0xFF);
					sptwb_ex.SetCbdValue(9, Constants.SPTWB_DATA_LENGTH & 0xFF);
					break;
				case Constants.SCSIOP_READ_ATTRIBUTES:
					sptwb_ex.SetCbdValue(0, opCode);
					sptwb_ex.SetCbdValue(10, (Constants.SPTWB_DATA_LENGTH >> 24) & 0xFF);
					sptwb_ex.SetCbdValue(11, (Constants.SPTWB_DATA_LENGTH >> 16) & 0xFF);
					sptwb_ex.SetCbdValue(12, (Constants.SPTWB_DATA_LENGTH >> 8) & 0xFF);
					sptwb_ex.SetCbdValue(13, Constants.SPTWB_DATA_LENGTH & 0xFF);
					break;
				default:
					sptwb_ex.SetCbdValue(0, opCode);
					break;
			}
			return ((uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucDataBuf))) +
				sptwb_ex.spt.DataInTransferLength;
		}

		private static uint ResetSrbOut(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, byte opCode)
		{
			byte cdbLength = GetCdbLength(opCode);
			if (cdbLength == 0) { return cdbLength; }

			sptwb_ex.Clear();
			sptwb_ex.spt.Version = 0;
			sptwb_ex.spt.Length = (uint)Marshal.SizeOf(typeof(Windows.Win32.Storage.IscsiDisc.SCSI_PASS_THROUGH_EX));
			sptwb_ex.spt.ScsiStatus = 0;
			sptwb_ex.spt.CdbLength = cdbLength;
			sptwb_ex.spt.StorAddressLength = (uint)Marshal.SizeOf<STOR_ADDR_BTL8>();
			sptwb_ex.spt.SenseInfoLength = Constants.SPT_SENSE_LENGTH;
			sptwb_ex.spt.DataOutTransferLength = 4 << 8;
			sptwb_ex.spt.DataInTransferLength = 0;
			sptwb_ex.spt.DataDirection = Constants.SCSI_IOCTL_DATA_OUT;
			sptwb_ex.spt.TimeOutValue = 2;
			sptwb_ex.StorAddress.Init();
			sptwb_ex.spt.StorAddressOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.StorAddress));
			sptwb_ex.spt.SenseInfoOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucSenseBuf));
			sptwb_ex.spt.DataOutBufferOffset =
				(uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucDataBuf));
			sptwb_ex.spt.DataInBufferOffset = 0;
			switch (opCode)
			{
				case Constants.SCSIOP_SECURITY_PROTOCOL_OUT:
					sptwb_ex.SetCbdValue(0, opCode);
					break;
				default:
					sptwb_ex.SetCbdValue(0, opCode);
					break;
			}
			return ((uint)Marshal.OffsetOf<NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX>(nameof(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX.ucDataBuf))) +
				sptwb_ex.spt.DataOutTransferLength;
		}

		private static uint CreateSecurityProtocolInSrb(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, byte securityProtocol, short pageCode)
		{
			uint length = ResetSrbIn(ref sptwb_ex, Constants.SCSIOP_SECURITY_PROTOCOL_IN);
			if (length == 0) { return length; }
			sptwb_ex.SetCbdValue(1, securityProtocol);
			sptwb_ex.SetCbdValue(2, (byte)((pageCode >> 8) & 0xFF));
			sptwb_ex.SetCbdValue(3, (byte)(pageCode & 0xFF));
			return length;
		}
		private static uint CreateSecurityProtocolOutSrb(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, byte securityProtocol, short pageCode)
		{
			uint length = ResetSrbOut(ref sptwb_ex, Constants.SCSIOP_SECURITY_PROTOCOL_OUT);
			if (length == 0) { return length; }
			sptwb_ex.SetCbdValue(1, securityProtocol);
			sptwb_ex.SetCbdValue(2, (byte)((pageCode >> 8) & 0xFF));
			sptwb_ex.SetCbdValue(3, (byte)(pageCode & 0xFF));

			return length;
		}
		private static uint CreateReadAttributeSrb(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, byte serviceAction)
		{
			uint length = ResetSrbIn(ref sptwb_ex, Constants.SCSIOP_READ_ATTRIBUTES);
			if (length == 0) { return length; }
			sptwb_ex.SetCbdValue(1, (byte)(serviceAction & 0x1F));
			return length;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct DATA_ENCRYPTION_CAPABILITIES
		{
			public ushort PageCode; /* Network Byte Order */
			public ushort PageLength; /* Network Byte Order */
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte5;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
			public byte[] Reserved2;
			public List<DATA_ENCRYPTION_ALGORITHM> AlgorithmList;

			private BitVector32.Section ConfigurationPrevented;
			private BitVector32.Section ExternalDataEncryptionCapable;
			private BitVector32.Section Reserved1;

			public void Init()
			{
				Byte5 = new(0);
				Reserved2 = new byte[15];
				AlgorithmList = new();
				ConfigurationPrevented = BitVector32.CreateSection(1 << 2 -1);
				ExternalDataEncryptionCapable = BitVector32.CreateSection(1 << 2 -1, ConfigurationPrevented);
				Reserved1 = BitVector32.CreateSection(1 << 4 -1, ExternalDataEncryptionCapable);
			}

			public void SetConfigurationPrevented(byte value)
			{
				Byte5[ConfigurationPrevented] = value;
			}
			public byte GetConfigurationPrevented()
			{
				return (byte)Byte5[ConfigurationPrevented];
			}
			public void SetExternalDataEncryptionCapable(byte value)
			{
				Byte5[ExternalDataEncryptionCapable] = value;
			}
			public byte GetExternalDataEncryptionCapable()
			{
				return (byte)Byte5[ExternalDataEncryptionCapable];
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct DATA_ENCRYPTION_ALGORITHM
		{
			public byte AlgorithmIndex;
			public byte Reserved3;
			public ushort DescriptorLength; /* Network Byte Order */
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte24;
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte25;
			public ushort UnauthKadMaxLength; /* Network Byte Order */
			public ushort AuthKadMaxLength; /* Network Byte Order */
			public ushort KeySize; /* Network Byte Order */
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte32;
			public byte Reserved4;
			public ushort MaximumSupplementalDecryptionKeyCount; /* Network Byte Order */
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public byte[] Reserved5;
			public uint AlgorithmCode; /* Network Byte Order */

			private BitVector32.Section EncryptCapable;
			private BitVector32.Section DecryptCapable;
			private BitVector32.Section DistinguishEncryptedLogicalBlockCapable;
			private BitVector32.Section MacKadCapable;
			private BitVector32.Section SupplementalDecryptionKeyCapable;
			private BitVector32.Section AlgorithmValidForMountedVolume;

			private BitVector32.Section AuthKadFixedLength;
			private BitVector32.Section UnauthKadFixedLength;
			private BitVector32.Section VolumeContainsEncryptedLogicalBlocksCapable;
			private BitVector32.Section KadFormatCapable;
			private BitVector32.Section NonceKadCapable;
			private BitVector32.Section AlgorithmValidForCurrentLogicalPosition;

			private BitVector32.Section EncryptionAlgorithmRecordsEncryptionMode;
			private BitVector32.Section RawDecryptionModeControlCapabilities;
			private BitVector32.Section ExternalEncryptionModeControlCapable;
			private BitVector32.Section DecryptionKadCapable;


			public void Init()
			{
				Byte24 = new(0);
				Byte25 = new(0);
				Reserved5 = new byte[4];
				EncryptCapable = BitVector32.CreateSection(1 << 2 - 1);
				DecryptCapable = BitVector32.CreateSection(1 << 2 - 1, EncryptCapable);
				DistinguishEncryptedLogicalBlockCapable = BitVector32.CreateSection(1 << 1 - 1, DecryptCapable);
				MacKadCapable = BitVector32.CreateSection(1 << 1 - 1, DistinguishEncryptedLogicalBlockCapable);
				SupplementalDecryptionKeyCapable = BitVector32.CreateSection(1 << 1 - 1, MacKadCapable);
				AlgorithmValidForMountedVolume = BitVector32.CreateSection(1 << 1 - 1, SupplementalDecryptionKeyCapable);
				AuthKadFixedLength = BitVector32.CreateSection(1 << 1 - 1);
				UnauthKadFixedLength = BitVector32.CreateSection(1 << 1 - 1, AuthKadFixedLength);
				VolumeContainsEncryptedLogicalBlocksCapable = BitVector32.CreateSection(1 << 1 - 1, UnauthKadFixedLength);
				KadFormatCapable = BitVector32.CreateSection(1 << 1 - 1, VolumeContainsEncryptedLogicalBlocksCapable);
				NonceKadCapable = BitVector32.CreateSection(1 << 2 - 1, KadFormatCapable);
				AlgorithmValidForCurrentLogicalPosition = BitVector32.CreateSection(1 << 2 - 1, NonceKadCapable);
				EncryptionAlgorithmRecordsEncryptionMode = BitVector32.CreateSection(1 << 1 - 1);
				RawDecryptionModeControlCapabilities = BitVector32.CreateSection(1 << 3 - 1, EncryptionAlgorithmRecordsEncryptionMode);
				ExternalEncryptionModeControlCapable = BitVector32.CreateSection(1 << 2 - 1, RawDecryptionModeControlCapabilities);
				DecryptionKadCapable = BitVector32.CreateSection(1 << 3 - 1, ExternalEncryptionModeControlCapable);
			}

			public void SetEncryptCapable(byte value)
			{
				Byte24[EncryptCapable] = value;
			}
			public bool IsEncryptCapable()
			{
				return Byte24[EncryptCapable] != 0;
			}
			public void SetDecryptCapable(byte value)
			{
				Byte24[DecryptCapable] = value;
			}
			public bool IsDecryptCapable()
			{
				return Byte24[DecryptCapable] != 0;
			}
			public void SetDistinguishEncryptedLogicalBlockCapable(byte value)
			{
				Byte24[DistinguishEncryptedLogicalBlockCapable] = value;
			}
			public void SetMacKadCapable(byte value)
			{
				Byte24[MacKadCapable] = value;
			}
			public void SetSupplementalDecryptionKeyCapable(byte value)
			{
				Byte24[SupplementalDecryptionKeyCapable] = value;
			}
			public void SetAlgorithmValidForMountedVolume(byte value)
			{
				Byte24[AlgorithmValidForMountedVolume] = value;
			}
			public void SetAuthKadFixedLength(byte value)
			{
				Byte25[AuthKadFixedLength] = value;
			}
			public bool RequiresAuthKadFixedLength()
			{
				return Byte25[AuthKadFixedLength] != 0;
			}
			public void SetUnauthKadFixedLength(byte value)
			{
				Byte25[UnauthKadFixedLength] = value;
			}
			public bool RequiresUnauthKadFixedLength()
			{
				return Byte25[UnauthKadFixedLength] != 0;
			}
			public void SetVolumeContainsEncryptedLogicalBlocksCapable(byte value)
			{
				Byte25[VolumeContainsEncryptedLogicalBlocksCapable] = value;
			}
			public void SetKadFormatCapable(byte value)
			{
				Byte25[KadFormatCapable] = value;
			}
			public bool IsKadFormatCapable()
			{
				return Byte25[KadFormatCapable] != 0;
			}
			public void SetNonceKadCapable(byte value)
			{
				Byte25[NonceKadCapable] = value;
			}
			public void SetAlgorithmValidForCurrentLogicalPosition(byte value)
			{
				Byte25[AlgorithmValidForCurrentLogicalPosition] = value;
			}
			public void SetEncryptionAlgorithmRecordsEncryptionMode(byte value)
			{
				Byte32[EncryptionAlgorithmRecordsEncryptionMode] = value;
			}
			public void SetRawDecryptionModeControlCapabilities(byte value)
			{
				Byte32[RawDecryptionModeControlCapabilities] = value;
			}
			public void SetExternalEncryptionModeControlCapable(byte value)
			{
				Byte32[ExternalEncryptionModeControlCapable] = value;
			}
			public void SetDecryptionKadCapable(byte value)
			{
				Byte32[DecryptionKadCapable] = value;
			}

		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct KEY_HEADER
		{
			public ushort PageCode; /* Network Byte Order */
			public ushort PageLength; /* Network Byte Order */
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte5; // Scope, Reserved1, Lock
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte6; // CheckExternalEncryptionMode, RawDecryptionModeControl, SupplementalDecryptionKey, ClearKeyOnDemount, ClearKeyOnReservationPreempted, ClearKeyOnReservationLoss
			public byte EncryptionMode;
			public byte DecriptionMode;
			public byte AlgorithmIndex;
			public byte KeyFormat;
			public byte KADFormat;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
			public byte[] Reserved2;
			public ushort KeyLength;
			[MarshalAs(UnmanagedType.ByValArray)]
			public byte[] KeyAndKADList;

			private BitVector32.Section Lock;
			private BitVector32.Section Reserved1;
			private BitVector32.Section Scope;

			private BitVector32.Section CheckExternalEncryptionMode;
			private BitVector32.Section RawDecryptionModeControl;
			private BitVector32.Section SupplementalDecryptionKey;
			private BitVector32.Section ClearKeyOnDemount;
			private BitVector32.Section ClearKeyOnReservationPreempted;
			private BitVector32.Section ClearKeyOnReservationLoss;

			public void Init()
			{
				Byte5 = new(0);
				Byte6 = new(0);
				Reserved2 = new byte[7];
				Lock = BitVector32.CreateSection(1 << 1 - 1);
				Reserved1 = BitVector32.CreateSection(1 << 4 - 1, Lock);
				Scope = BitVector32.CreateSection(1 << 3 - 1, Reserved1);
				CheckExternalEncryptionMode = BitVector32.CreateSection(1 << 2 - 1);
				RawDecryptionModeControl = BitVector32.CreateSection(1 << 2 - 1, CheckExternalEncryptionMode);
				SupplementalDecryptionKey = BitVector32.CreateSection(1 << 1 - 1, RawDecryptionModeControl);
				ClearKeyOnDemount = BitVector32.CreateSection(1 << 1 - 1, SupplementalDecryptionKey);
				ClearKeyOnReservationPreempted = BitVector32.CreateSection(1 << 1 - 1, ClearKeyOnDemount);
				ClearKeyOnReservationLoss = BitVector32.CreateSection(1 << 1 - 1, ClearKeyOnReservationPreempted);
			}

			public void Clear()
			{
				PageCode = default;
				PageLength = default;
				SetLock(0);
				SetScope(0);
				SetCheckExternalEncryptionMode(0);
				SetRawDecryptionModeControl(0);
				SetSupplementalDecryptionKey(0);
				SetClearKeyOnDemount(0);
				SetClearKeyOnReservationPreempted(0);
				SetClearKeyOnReservationLoss(0);
			}

			public bool TryGetBytes([NotNullWhen(true)] out byte[]? data, [NotNullWhen(true)] out int? length)
			{
				data = null;
				length = null;
				using MemoryStream memoryStream = new(KeyAndKADList is null ? 20 : 20 + KeyAndKADList.Length);
				using BinaryWriter descriptorWriter = new(memoryStream, Encoding.ASCII, true);
				descriptorWriter.Write(PageCode);
				descriptorWriter.Write(PageLength);
				descriptorWriter.Write((byte)Byte5.Data);
				descriptorWriter.Write((byte)Byte6.Data);
				descriptorWriter.Write(EncryptionMode);
				descriptorWriter.Write(DecriptionMode);
				descriptorWriter.Write(AlgorithmIndex);
				descriptorWriter.Write(KeyFormat);
				descriptorWriter.Write(KADFormat);
				if (Reserved2 is not null)
				{
					descriptorWriter.Write(Reserved2);
				}
				descriptorWriter.Write(KeyLength);
				if (KeyAndKADList is not null)
				{
					descriptorWriter.Write(KeyAndKADList);
				}
				descriptorWriter.Flush();
				data = memoryStream.ToArray();
				length = data.Length;
				descriptorWriter.Close();
				return true;
			}

			public void SetLock(byte value)
			{
				Byte5[Lock] = value;
			}

			public void SetScope(byte value)
			{
				Byte5[Scope] = value;
			}

			public void SetCheckExternalEncryptionMode(byte value)
			{
				Byte6[CheckExternalEncryptionMode] = value;
			}

			public void SetRawDecryptionModeControl(byte value)
			{
				Byte6[RawDecryptionModeControl] = value;
			}

			public void SetSupplementalDecryptionKey(byte value)
			{
				Byte6[SupplementalDecryptionKey] = value;
			}

			public void SetClearKeyOnDemount(byte value)
			{
				Byte6[ClearKeyOnDemount] = value;
			}

			public void SetClearKeyOnReservationPreempted(byte value)
			{
				Byte6[ClearKeyOnReservationPreempted] = value;
			}

			public void SetClearKeyOnReservationLoss(byte value)
			{
				Byte6[ClearKeyOnReservationLoss] = value;
			}
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
		public struct PLAIN_KEY_DESCRIPTOR
		{
			public byte Type;
			[MarshalAs(UnmanagedType.U1)]
			public BitVector32 Byte2;
			public ushort Length;
			public byte[] Descriptor;

			private BitVector32.Section Authenticated;
			private BitVector32.Section Reserved1;
			private readonly static ushort DescriptorOffset = 4;

			public void Init()
			{
				Byte2 = new(0);
				Authenticated = BitVector32.CreateSection(1 << 3 - 1);
				Reserved1 = BitVector32.CreateSection(1 << 5 - 1, Authenticated);
			}

			public ushort GetLength()
			{
				return (ushort)(DescriptorOffset + Descriptor.Length);
			}

			public static ushort GetLength(ushort descriptorLength)
			{
				return (ushort)(DescriptorOffset + descriptorLength);
			}

			public bool TryGetBytes([NotNullWhen(true)] out byte[]? data, [NotNullWhen(true)] out int? length)
			{
				data = null;
				length = null;
				using MemoryStream memoryStream = new(GetLength());
				using BinaryWriter descriptorWriter = new(memoryStream, Encoding.ASCII, true);
				descriptorWriter.Write(Type);
				descriptorWriter.Write((byte)Byte2.Data);
				descriptorWriter.Write(Length);
				if (Descriptor is not null)
				{
					descriptorWriter.Write(Descriptor);
				}
				descriptorWriter.Flush();
				data = memoryStream.ToArray();
				length = data.Length;
				descriptorWriter.Close();
				return true;
			}

			public void SetAuthenticated(byte value)
			{
				Byte2[Authenticated] = value;
			}
		}

		public static ushort ProcessKey(int keyFormat, int keyType, int keyLength, ref byte[]? key, ushort wrappedDescriptorsLength, ref byte[]? wrappedDescriptors, out byte[]? keyField)
		{
			keyField = null;
			ushort keyFieldLength = 0;

			if (keyFormat == Constants.SPIN_TAPE_KEY_FORMAT_WRAPPED)
			{
				if (keyFormat < 0 || keyFormat > 0xFFFF ||
					keyType < 0 || keyType > 0xFFFF ||
					keyLength < 0 || keyLength > 0xFFFF)
				{
					return 0;
				}

				ushort parameterSet, labelLength, wrappedKeyLength, signatureLength = 0;
				keyFieldLength = (ushort)(sizeof(ushort) + sizeof(ushort) + wrappedDescriptorsLength + sizeof(ushort) + keyLength + sizeof(ushort));

				using MemoryStream memoryStream = new(keyFieldLength);
				using BinaryWriter descriptorWriter = new(memoryStream, Encoding.ASCII, true);
				parameterSet = ReverseByteOrder((ushort)(keyType & 0xFFFF));
				descriptorWriter.Write(parameterSet);
				labelLength = ReverseByteOrder((ushort)(wrappedDescriptorsLength & 0xFFFF));
				descriptorWriter.Write(labelLength);
				if (wrappedDescriptors is not null)
				{
					descriptorWriter.Write(wrappedDescriptors);
				}
				wrappedKeyLength = ReverseByteOrder((ushort)(keyLength & 0xFFFF));
				descriptorWriter.Write(wrappedKeyLength);
				if (key is not null)
				{
					descriptorWriter.Write(key);
				}
				signatureLength = ReverseByteOrder(signatureLength);
				descriptorWriter.Write(signatureLength);
				descriptorWriter.Flush();
				keyField = memoryStream.ToArray();
				keyFieldLength = (ushort)keyField.Length;
				descriptorWriter.Close();
			}

			return (ushort)(keyField != null ? keyFieldLength : 0);
		}

		public static bool TryProcessKad(bool clearKey, ushort keyAssociatedDataLength, byte[]? keyAssociatedData, DATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, out ushort kadFieldLength, out List<PLAIN_KEY_DESCRIPTOR>? kadField)
		{
			kadField = null;
			kadFieldLength = 0;
			// Return early if there is no KAD to process
			if (clearKey || keyAssociatedData == null)
			{
				return true;
			}

			ushort maxKadLength = (ushort)(encryptionAlgorithm.IsKadFormatCapable() ? encryptionAlgorithm.AuthKadMaxLength + encryptionAlgorithm.UnauthKadMaxLength : encryptionAlgorithm.AuthKadMaxLength);

			// If KADF is supported, and descriptor overflows both A-KAD and U-KAD Fields
			if (encryptionAlgorithm.IsKadFormatCapable() && keyAssociatedDataLength > maxKadLength)
			{
				return false;
			}
			// If KADF is supported, and descriptor doesn't overflow A-KAD field
			else if (encryptionAlgorithm.IsKadFormatCapable() && keyAssociatedDataLength <= encryptionAlgorithm.AuthKadMaxLength)
			{
				// If A-KAD length is fixed (AKADF), does the descriptor meet the required length?
				if (encryptionAlgorithm.RequiresAuthKadFixedLength() && keyAssociatedDataLength != encryptionAlgorithm.AuthKadMaxLength)
				{
					return false;
				}
			}

			// Calculate the length of aKad->Descriptor
			ushort aKadDescriptorLength = 0;
			if (encryptionAlgorithm.RequiresAuthKadFixedLength() || keyAssociatedDataLength > encryptionAlgorithm.AuthKadMaxLength)
			{
				aKadDescriptorLength = encryptionAlgorithm.AuthKadMaxLength;
			}
			else
			{
				aKadDescriptorLength = keyAssociatedDataLength;
			}
			// Calculate the length of aKad
			ushort aKadLength = PLAIN_KEY_DESCRIPTOR.GetLength(aKadDescriptorLength);
			// Calculate the length of uKad->Descriptor
			ushort uKadDescriptorLength = 0;
			if (encryptionAlgorithm.RequiresUnauthKadFixedLength() && keyAssociatedDataLength > encryptionAlgorithm.AuthKadMaxLength)
			{
				uKadDescriptorLength = encryptionAlgorithm.UnauthKadMaxLength;
			}
			else if (keyAssociatedDataLength > encryptionAlgorithm.AuthKadMaxLength)
			{
				uKadDescriptorLength = (ushort)(keyAssociatedDataLength - encryptionAlgorithm.AuthKadMaxLength);
			}
			// Calculate the length of uKad
			ushort uKadLength = uKadDescriptorLength == 0 ? (ushort)0 : PLAIN_KEY_DESCRIPTOR.GetLength(uKadDescriptorLength);

			// Calculate the combined lengths of aKad and uKad
			kadFieldLength = (ushort)(aKadLength + uKadLength);
			// Allocate memory to store KAD list
			kadField = new();
			if (kadField == null)
			{
				return false;
			}
			// Update pointer for KAD list to new location
			// U-KAD descriptor (0x00) comes before A-KAD descriptor (0x01) in KAD list; set pointers for both
			PLAIN_KEY_DESCRIPTOR uKad = new();
			PLAIN_KEY_DESCRIPTOR aKad = new();
			// Create U-KAD if necessary
			if (keyAssociatedDataLength > encryptionAlgorithm.AuthKadMaxLength)
			{
				uKad.Type = Constants.SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH;
				uKad.Length = ReverseByteOrder(uKadDescriptorLength);
				uKad.Descriptor = new byte[uKadDescriptorLength];
				Array.Copy(keyAssociatedData, aKadDescriptorLength, uKad.Descriptor, 0, uKadDescriptorLength);
				kadField.Add(uKad);
			}
			// Create A-KAD
			aKad.Type = Constants.SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH;
			aKad.Length = ReverseByteOrder(aKadDescriptorLength);
			aKad.Descriptor = new byte[aKadDescriptorLength];
			Array.Copy(keyAssociatedData, 0, aKad.Descriptor, 0, aKadDescriptorLength);
			kadField.Add(aKad);

			return true;
		}

		private static void SetDataEncryption(ref NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, uint allocationLength, byte aesGcmAlgorithmIndex, bool clearKey, byte keyFormat, ushort keyFieldLength, byte[]? keyField, int kadFieldLength, List<PLAIN_KEY_DESCRIPTOR>? kad)
		{
			sptwb_ex.SetCbdValue(6, (byte)((allocationLength >> 24) & 0xFF));
			sptwb_ex.SetCbdValue(7, (byte)((allocationLength >> 16) & 0xFF));
			sptwb_ex.SetCbdValue(8, (byte)((allocationLength >> 8) & 0xFF));
			sptwb_ex.SetCbdValue(9, (byte)(allocationLength & 0xFF));
			ushort pageLength = (ushort)(allocationLength - 4);
			sptwb_ex.spt.DataOutTransferLength = 4 + (uint)pageLength;

			KEY_HEADER keyHeader = new();
			keyHeader.Init();
			keyHeader.PageCode = ReverseByteOrder(Constants.SPOUT_TAPE_SET_DATA_ENCRYPTION);
			keyHeader.PageLength = ReverseByteOrder(pageLength);
			keyHeader.SetScope(0x2);
			keyHeader.EncryptionMode = (byte)(clearKey ? 0x0 : 0x2);
			keyHeader.DecriptionMode = (byte)(clearKey ? 0x0 : 0x2);
			keyHeader.AlgorithmIndex = aesGcmAlgorithmIndex;
			keyHeader.KeyFormat = keyFormat;
			if (kad is not null)
			{
				keyHeader.KADFormat = Constants.SPOUT_TAPE_KAD_FORMAT_ASCII;
			}
			keyHeader.KeyLength = ReverseByteOrder(keyFieldLength);
			keyHeader.KeyAndKADList = new byte[keyFieldLength + kadFieldLength];
			if (keyField is not null)
			{
				Array.Copy(keyField, 0, keyHeader.KeyAndKADList, 0, keyFieldLength);
			}
			if (kad is not null)
			{
				int kadFieldPos = 0;
				foreach (PLAIN_KEY_DESCRIPTOR kd in kad)
				{
					if (kd.TryGetBytes(out byte[]? data, out int? length))
					{
						Array.Copy(data, 0, keyHeader.KeyAndKADList, keyFieldLength + kadFieldPos, length.Value);
						kadFieldPos += length.Value;
					}
				}
			}
			if (keyHeader.TryGetBytes(out byte[]? keyHeaderBytes, out int? keyHeaderLength))
			{
				Array.Copy(keyHeaderBytes, 0, sptwb_ex.ucDataBuf, 0, keyHeaderLength.Value);
			}
		}

		public static void EnableTapeDriveEncryption(TapeDrive tapeDrive, ref byte[]? wrappedKey, string? kad)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			if (wrappedKey is null || tapeDrive.WrappedKeyDescriptors is null)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateSecurityProtocolOutSrb(ref sptwb_ex, Constants.SECURITY_PROTOCOL_TAPE, Constants.SPOUT_TAPE_SET_DATA_ENCRYPTION);
			if (kad is not null && SPTI.LTO.TryProcessKad(false, (ushort)kad.Length, Encoding.ASCII.GetBytes(kad), tapeDrive.DataEncryptionAlgorithms[0], out ushort kadFieldLength, out List<LTO.PLAIN_KEY_DESCRIPTOR>? kadField))
			{
				byte[]? wrappedKeyDescriptors = tapeDrive.WrappedKeyDescriptors;
				ushort keyFieldLength = SPTI.LTO.ProcessKey(Constants.SPIN_TAPE_KEY_FORMAT_WRAPPED, Constants.SPIN_TAPE_PUBKEY_TYPE_RSA2048, wrappedKey.Length, ref wrappedKey, (ushort)tapeDrive.WrappedKeyDescriptors.Length, ref wrappedKeyDescriptors, out byte[]? keyField);
				ushort allocationLength = (ushort)(20 + keyFieldLength + kadFieldLength);
				SPTI.LTO.SetDataEncryption(ref sptwb_ex, allocationLength, tapeDrive.DataEncryptionAlgorithms[0].AlgorithmIndex, false, Constants.SPIN_TAPE_KEY_FORMAT_WRAPPED, keyFieldLength, keyField, kadFieldLength, kadField);
				bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
				if (ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
				{
					Trace.WriteLine("Decryption successfully enabled for drive.");
				}
				else if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
				{
					ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
				}
				else if (!ok || sptwb_ex.spt.ScsiStatus != Constants.SCSISTAT_GOOD)
				{
					int error = Marshal.GetLastWin32Error();
					Marshal.ThrowExceptionForHR(error);
				}
				else
				{
					Trace.WriteLine("Unreachable?");
				}
			}
		}

		public static void DisableTapeDriveEncryption(TapeDrive tapeDrive)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateSecurityProtocolOutSrb(ref sptwb_ex, Constants.SECURITY_PROTOCOL_TAPE, Constants.SPOUT_TAPE_SET_DATA_ENCRYPTION);
			uint allocationLength = 20;
			SetDataEncryption(ref sptwb_ex, allocationLength, 1, true, 0, 0, null, 0, null);
			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
			}
			if (!ok)
			{
				int error = Marshal.GetLastWin32Error();
				Marshal.ThrowExceptionForHR(error);
			}
			if (ok)
			{
				Trace.WriteLine("Decryption successfully turned off for drive.");
			}
		}

		public static void GetTapeDriveIdentifiers(TapeDrive tapeDrive)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = ResetSrbIn(ref sptwb_ex, Constants.SCSIOP_INQUIRY);
			sptwb_ex.SetCbdValue(2, Constants.VPD_DEVICE_IDENTIFIERS);
			sptwb_ex.SetCbdValue(1, Constants.CDB_INQUIRY_EVPD);

			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			PrintCdb(sptwb_ex);
			if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
			}
			if (!ok)
			{
				int error = Marshal.GetLastWin32Error();
				Marshal.ThrowExceptionForHR(error);
			}
			if (ok)
			{
				//Trace.WriteLine(Convert.ToHexString(sptwb_ex.ucDataBuf, 0, (int)sptwb_ex.spt.DataInTransferLength));
				VPD_IDENTIFICATION_PAGE page = new();
				page.Byte1 = sptwb_ex.ucDataBuf[0];
				page.PageCode = sptwb_ex.ucDataBuf[1];
				page.PageLength = sptwb_ex.ucDataBuf[3];
				page.Descriptors = new();
				int descriptorLength = 0;
				for (int i = 4; i < 4 + page.PageLength; i += 4 + descriptorLength)
				{
					VPD_IDENTIFICATION_DESCRIPTOR descriptor = new();
					descriptor.Byte1 = sptwb_ex.ucDataBuf[i];
					descriptor.Byte2 = sptwb_ex.ucDataBuf[i + 1];
					descriptor.Byte3 = sptwb_ex.ucDataBuf[i + 2];
					descriptor.IdentifierLength = sptwb_ex.ucDataBuf[i + 3];
					descriptorLength = descriptor.IdentifierLength;
					descriptor.Identifier = new byte[descriptorLength];
					Array.Copy(sptwb_ex.ucDataBuf, i + 4, descriptor.Identifier, 0, descriptorLength);
					page.Descriptors.Add(descriptor);
					if (page.Descriptors.Count == 1)
					{
						tapeDrive.LogicalUnitIdentifier = Convert.ToHexString(descriptor.Identifier);
						break; // Only need LUN, which is always the first descriptor
					}
				}
				//Trace.WriteLine(Convert.ToHexString(page.Descriptors, 0, page.PageLength));
			}
		}

		public static void GetTapeDriveDataEncryptionCapabilities(TapeDrive tapeDrive)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateSecurityProtocolInSrb(ref sptwb_ex, Constants.SECURITY_PROTOCOL_TAPE, Constants.SPIN_TAPE_ENCRYPTION_CAPABILITIES);
			PrintCdb(sptwb_ex);

			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
			}
			if (!ok)
			{
				int error = Marshal.GetLastWin32Error();
				Marshal.ThrowExceptionForHR(error);
			}
			if (ok)
			{
				tapeDrive.DataEncryptionAlgorithms.Clear();
				//Trace.WriteLine(Convert.ToHexString(sptwb_ex.ucDataBuf, 0, (int)sptwb_ex.spt.DataInTransferLength));
				DATA_ENCRYPTION_CAPABILITIES page = new();
				page.Init();
				using BinaryReader reader = new(new MemoryStream(sptwb_ex.ucDataBuf));
				page.PageCode = ReverseByteOrder(reader.ReadUInt16());
				page.PageLength = ReverseByteOrder(reader.ReadUInt16());
				byte Byte5 = reader.ReadByte();
				page.SetConfigurationPrevented((byte)(Byte5 & 0b00000011));
				page.SetExternalDataEncryptionCapable((byte)(Byte5 >> 2 & 0b00000011));
				page.Reserved2 = reader.ReadBytes(15);
				ushort algorithmListLength = (ushort)(page.PageLength + 4 - reader.BaseStream.Position);
				ushort algorithmIndexCount = (ushort)(algorithmListLength / 24); // 24 bytes per algorithm? Marshal.SizeOf<DATA_ENCRYPTION_ALGORITHM>()
				for (uint i = 0; i < algorithmIndexCount; i++)
				{
					DATA_ENCRYPTION_ALGORITHM currentAlgorithm = new();
					currentAlgorithm.Init();
					currentAlgorithm.AlgorithmIndex = reader.ReadByte();
					currentAlgorithm.Reserved3 = reader.ReadByte();
					currentAlgorithm.DescriptorLength = ReverseByteOrder(reader.ReadUInt16());
					byte Byte24 = reader.ReadByte();
					currentAlgorithm.SetEncryptCapable((byte)(Byte24 & 0b00000011));
					currentAlgorithm.SetDecryptCapable((byte)(Byte24 >> 2 & 0b00000011));
					currentAlgorithm.SetDistinguishEncryptedLogicalBlockCapable((byte)(Byte24 >> 4 & 0b00000001));
					currentAlgorithm.SetMacKadCapable((byte)(Byte24 >> 5 & 0b00000001));
					currentAlgorithm.SetSupplementalDecryptionKeyCapable((byte)(Byte24 >> 6 & 0b00000001));
					currentAlgorithm.SetAlgorithmValidForMountedVolume((byte)(Byte24 >> 7 & 0b00000001));
					byte Byte25 = reader.ReadByte();
					currentAlgorithm.SetAuthKadFixedLength((byte)(Byte25 & 0b00000001));
					currentAlgorithm.SetUnauthKadFixedLength((byte)(Byte25 >> 1 & 0b00000001));
					currentAlgorithm.SetVolumeContainsEncryptedLogicalBlocksCapable((byte)(Byte25 >> 2 & 0b00000001));
					currentAlgorithm.SetKadFormatCapable((byte)(Byte25 >> 3 & 0b00000001));
					currentAlgorithm.SetNonceKadCapable((byte)(Byte25 >> 4 & 0b00000011));
					currentAlgorithm.SetAlgorithmValidForCurrentLogicalPosition((byte)(Byte25 >> 6 & 0b00000011));
					currentAlgorithm.UnauthKadMaxLength = ReverseByteOrder(reader.ReadUInt16());
					currentAlgorithm.AuthKadMaxLength = ReverseByteOrder(reader.ReadUInt16());
					currentAlgorithm.KeySize = ReverseByteOrder(reader.ReadUInt16());
					byte Byte32 = reader.ReadByte();
					currentAlgorithm.SetEncryptionAlgorithmRecordsEncryptionMode((byte)(Byte32 & 0b00000001));
					currentAlgorithm.SetRawDecryptionModeControlCapabilities((byte)(Byte32 >> 1 & 0b00000111));
					currentAlgorithm.SetExternalEncryptionModeControlCapable((byte)(Byte32 >> 4 & 0b00000011));
					currentAlgorithm.SetDecryptionKadCapable((byte)(Byte32 >> 6 & 0b00000011));
					currentAlgorithm.Reserved4 = reader.ReadByte();
					currentAlgorithm.MaximumSupplementalDecryptionKeyCount = ReverseByteOrder(reader.ReadUInt16());
					currentAlgorithm.Reserved5 = reader.ReadBytes(4);
					currentAlgorithm.AlgorithmCode = ReverseByteOrder(reader.ReadUInt32());
					tapeDrive.DataEncryptionAlgorithms.Add(currentAlgorithm);
				}
				reader.Close();
			}
		}

		static void PrintCdb(NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex)
		{
			byte[] cdb = new byte[sptwb_ex.spt.CdbLength];
			for (int i = 0; i < cdb.Length; i++)
			{
				cdb[i] = Windows.Win32.InlineArrayIndexerExtensions.ReadOnlyItemRef(sptwb_ex.spt.Cdb, i);
			}
			//Trace.WriteLine($"CDB: {Convert.ToHexString(cdb)}");
		}

		public static ushort ReverseByteOrder(ushort value)
		{
			return (ushort)((value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8);
		}

		public static uint ReverseByteOrder(uint value)
		{
			return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 | (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
		}

		public static ulong ReverseByteOrder(ulong value)
		{
			return (value & 0x00000000000000FFUL) << 56 | (value & 0x000000000000FF00UL) << 40 | (value & 0x0000000000FF0000UL) << 24 | (value & 0x00000000FF000000UL) << 8 |
				(value & 0x000000FF00000000UL) >> 8 | (value & 0x0000FF0000000000UL) >> 24 | (value & 0x00FF000000000000UL) >> 40 | (value & 0xFF00000000000000UL) >> 56;
		}

		public static void GetTapeDriveKeyWrapKey(TapeDrive tapeDrive)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateSecurityProtocolInSrb(ref sptwb_ex, Constants.SECURITY_PROTOCOL_TAPE, Constants.SPIN_TAPE_WRAPPED_PUBKEY);
			PrintCdb(sptwb_ex);

			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
			}
			if (!ok)
			{
				int error = Marshal.GetLastWin32Error();
				Marshal.ThrowExceptionForHR(error);
			}
			if (ok)
			{
				//Trace.WriteLine(Convert.ToHexString(sptwb_ex.ucDataBuf, 0, (int)sptwb_ex.spt.DataInTransferLength));
				DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY page = new();
				using BinaryReader reader = new(new MemoryStream(sptwb_ex.ucDataBuf));
				page.PageCode = ReverseByteOrder(reader.ReadUInt16());
				page.PageLength = ReverseByteOrder(reader.ReadUInt16());
				page.PublicKeyType = ReverseByteOrder(reader.ReadUInt32());
				page.PublicKeyFormat = ReverseByteOrder(reader.ReadUInt32());
				page.PublicKeyLength = ReverseByteOrder(reader.ReadUInt16());
				if (page.PublicKeyType == Constants.SPIN_TAPE_PUBKEY_TYPE_RSA2048 && page.PublicKeyFormat == Constants.SPIN_TAPE_PUBKEY_FORMAT_RSA2048 && page.PublicKeyLength == Constants.SPIN_TAPE_PUBKEY_LENGTH_RSA2048)
				{
					page.PublicKey = new byte[page.PublicKeyLength];
					int keyByteLength = reader.Read(page.PublicKey, 0, page.PublicKeyLength);
					if (keyByteLength == page.PublicKeyLength)
					{
						// SPIN_TAPE_PUBKEY_FORMAT_RSA2048: page.PublicKey is 512 bytes, first 256 contain zero-padding and the modulus, last 256 contain zero-padding and the exponent
						// Get the modulus, without zero-padding
						byte[] modulus = new byte[256];
						int modulusStartPos = Array.FindIndex(page.PublicKey, 0, 256, (x) => x != 0x00);
						byte[] realModulus = new byte[256 - modulusStartPos];
						Array.Copy(page.PublicKey, modulusStartPos, realModulus, 0, realModulus.Length);
						// Get the exponent, without zero-padding
						byte[] exponent = new byte[256];
						int exponentStartPos = Array.FindIndex(page.PublicKey, 256, 256, (x) => x != 0x00);
						byte[] realExponent = new byte[512 - exponentStartPos];
						Array.Copy(page.PublicKey, exponentStartPos, realExponent, 0, realExponent.Length);

						// Convert the modulus and padding into a PKCS#1 byte array (i.e. DER format RSA public key)
						using RSACryptoServiceProvider RSA = new();
						RSAParameters rsaParams = new()
						{
							Modulus = realModulus,
							Exponent = realExponent
						};
						RSA.ImportParameters(rsaParams);
						tapeDrive.KeyWrapPublicKey = RSA.ExportRSAPublicKey();

						// AES key wrapping (RFC 3447) uses RSAES-OAEP-ENCRYPT
						// L (the label parameter in RSAES-OAEP-ENCRYPT) = wrapped key descriptors in LTO
						// The wrapped key descriptors are concatenated together to form the L parameter
						// The descriptors must be in WRAPPED_KEY_DESCRIPTOR.Type order
						// Type 0x0: Device server identification (LUN/WWN)
						// Type 0x4: Wrapped key length (always 256 bytes for a 2048-bit/256-byte RSA public key)

						// Key descriptor type 0x0 - device server ID (probably an 8 byte long WWN, but 16 byte WWNs exist)
						WRAPPED_KEY_DESCRIPTOR lunKeyDescriptor = new();
						lunKeyDescriptor.Type = Constants.WRAPPED_KEY_DESCRIPTOR_TYPE_DEVICE_ID;
						ushort lunByteLength = (ushort)(tapeDrive.LogicalUnitIdentifier.Length / 2);
						lunKeyDescriptor.Length = ReverseByteOrder(lunByteLength);
						lunKeyDescriptor.Descriptor = new byte[lunByteLength];
						lunKeyDescriptor.Descriptor = Convert.FromHexString(tapeDrive.LogicalUnitIdentifier);

						// Key descriptor type 0x4 - wrapped key length (256 bytes)
						WRAPPED_KEY_DESCRIPTOR keyLengthKeyDescriptor = new();
						keyLengthKeyDescriptor.Type = Constants.WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_LENGTH;
						keyLengthKeyDescriptor.Length = ReverseByteOrder(2); // The decimal value 256 takes 2 bytes to store
						keyLengthKeyDescriptor.Descriptor = new byte[keyLengthKeyDescriptor.Length];
						ushort reversedKeyLength = ReverseByteOrder(256);
						keyLengthKeyDescriptor.Descriptor = BitConverter.GetBytes(reversedKeyLength);

						int descriptor1Length = Marshal.SizeOf(lunKeyDescriptor);
						int descriptor2Length = Marshal.SizeOf(keyLengthKeyDescriptor);
						int descriptorsLength = descriptor1Length + descriptor2Length;

						using MemoryStream memoryStream = new(descriptorsLength);
						using BinaryWriter descriptorWriter = new(memoryStream, Encoding.ASCII, true);
						descriptorWriter.Write(lunKeyDescriptor.Type);
						descriptorWriter.Write(lunKeyDescriptor.Reserved1);
						descriptorWriter.Write(lunKeyDescriptor.Length);
						descriptorWriter.Write(lunKeyDescriptor.Descriptor);
						descriptorWriter.Write(keyLengthKeyDescriptor.Type);
						descriptorWriter.Write(keyLengthKeyDescriptor.Reserved1);
						descriptorWriter.Write(keyLengthKeyDescriptor.Length);
						descriptorWriter.Write(keyLengthKeyDescriptor.Descriptor);
						descriptorWriter.Flush();
						tapeDrive.WrappedKeyDescriptors = memoryStream.ToArray();
						descriptorWriter.Close();

						//Trace.WriteLine(Convert.ToHexString(tapeDrive.WrappedKeyDescriptors));
					}
				}
			}
		}
	}
}
