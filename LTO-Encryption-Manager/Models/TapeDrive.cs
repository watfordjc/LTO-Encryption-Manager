using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using uk.JohnCook.dotnet.LTOEncryptionManager.SPTI;
using Windows.Win32.Storage.FileSystem;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Models
{
	public class RawMamAttribute
	{
		public ushort ID;
		public BitVector32 Byte3;
		public byte[]? RawData;

		private BitVector32.Section Format;
		private BitVector32.Section Reserved1;
		private BitVector32.Section ReadOnly;

		public bool IsReadOnly => Byte3[ReadOnly] == 1;

		public RawMamAttribute()
		{
			Byte3 = new(0);
			Format = BitVector32.CreateSection(1 << 2 - 1);
			Reserved1 = BitVector32.CreateSection(1 << 5 - 1, Format);
			ReadOnly = BitVector32.CreateSection(1 << 1 - 1, Reserved1);
		}

		public void SetReadOnly(byte readOnly)
		{
			Byte3[ReadOnly] = readOnly;
		}

		public void SetFormat(byte format)
		{
			Byte3[Format] = format;
		}

		public void SetAttributeLength(ushort length)
		{
			RawData = new byte[length];
		}

		public uint GetFormat()
		{
			return Byte3[Format] switch
			{
				0b00 => Constants.MAM_FORMAT_BINARY,
				0b01 => Constants.MAM_FORMAT_ASCII,
				0b10 => Constants.MAM_FORMAT_TEXT,
				0b11 => Constants.MAM_FORMAT_RESERVED,
				_ => throw new NotImplementedException()
			};
		}
	}

	public class TapeDriveTape
	{
		public string? Barcode { get; set; } = null;
		public bool? IsCompressed { get; set; } = null;
		public bool? IsEncrypted { get; set; } = null;
		public string? AuthKadString { get; set; } = null;
		public string? UnauthKadString { get; set; } = null;
		public string? KadString
		{
			get
			{
				return AuthKadString == null ? null : string.Concat(AuthKadString, UnauthKadString);
			}
		}
		public long? FirstEncryptedBlock { get; set; } = null;
		public long? FirstUnencryptedBlock { get; set; } = null;
		public byte? AlgorithmIndex { get; set; } = null;
		public string? ApplicationName { get; set; } = null;
		public bool? IsLtfsFormatted
		{
			get
			{
				return ApplicationName?.StartsWith("LTFS ");
			}
		}
		public string? PartitionTextLabel { get; set; } = null;
		public byte? VolumeLocked { get; set; } = null;

		public List<RawMamAttribute>[] MamRawAttributes { get; set; } = [[], [], [], []];
		public ulong[] PartitionsCapacity { get; set; } = new ulong[4];
		public ulong[] PartitionsCapacityRemaining { get; set; } = new ulong[4];
	}
	public class TapeDriveState
	{
		public event EventHandler<int>? ScsiStatusChanged;
		public event EventHandler<TapeDriveErrorEventArgs>? ErrorMessageChanged;
		public DateTime? LastExceptionTime { get; set; } = null;
		public Exception? LastException { get; set; } = null;
		public DateTime? LastHResultTime { get; set; } = null;
		public int LastHResult { get; set; } = 0;
		public DateTime? LastScsiStatusTime { get; set; } = null;
		private int _scsiStatus = 0;
		public int LastScsiStatus
		{
			get
			{
				return _scsiStatus;
			}
			set
			{
				_scsiStatus = value;
				LastScsiStatusTime = DateTime.Now;
				ScsiStatusChanged?.Invoke(this, value);
			}
		}
		public DateTime? LastSenseInfoTime { get; set; } = null;
		public byte[]? LastSenseInfo { get; set; } = null;

		public DateTime? LastErrorMessageTime { get; set; } = null;
		private string _errorMessage = string.Empty;
		public string LastErrorMessage
		{
			get
			{
				return _errorMessage;
			}
			set
			{
				_errorMessage = value;
				LastErrorMessageTime = DateTime.Now;
				ErrorMessageChanged?.Invoke(this, new(value));
			}
		}
		public string DisplayLastErrorMessage
		{
			get
			{
				return LastErrorMessageTime == null ? "Drive Status: No recent errors" : string.Concat("Drive Status at ", LastErrorMessageTime.ToString(), " : ", LastErrorMessage);
			}
		}
		public TapeDriveTape? CurrentTape { get; set; } = null;
	}

	/// <summary>
	/// An LTO Tape device
	/// </summary>
	public class TapeDrive
	{
		/// <summary>
		/// The <see cref="Guid"/> for a tape device interface
		/// </summary>
		static Guid GUID_DEVINTERFACE_TAPE = new("{53F5630B-B6BF-11D0-94F2-00A0C91EFB8B}");
		/// <summary>
		/// The device's identifier
		/// </summary>
		public string DeviceId { get; set; } = string.Empty;
		/// <summary>
		/// The full file path for opening the device
		/// </summary>
		public string Path => string.Concat(@"\\?\", DeviceId.Replace("\\", "#"), "#{", GUID_DEVINTERFACE_TAPE.ToString(), "}");
		/// <summary>
		/// A <see cref="SafeFileHandle"/> opened for the drive's <see cref="Path"/>
		/// </summary>
		public SafeFileHandle? Handle { get; set; }
		/// <summary>
		/// The device's display caption
		/// </summary>
		public string Caption { get; set; } = string.Empty;
		/// <summary>
		/// The device's serial number
		/// </summary>
		public string SerialNumber { get; set; } = string.Empty;
		/// <summary>
		/// The device's unique display caption (includes serial number)
		/// </summary>
		public string DeviceUIName => string.Concat(Caption, " [", SerialNumber, "]");
		/// <summary>
		/// The device's alignment mask
		/// </summary>
		public uint AlignmentMask { get; set; } = 0;
		/// <summary>
		/// The device's SCSI Request Block (SRB) type
		/// </summary>
		/// <remarks>Only <see cref="Windows.Win32.PInvoke.SRB_TYPE_STORAGE_REQUEST_BLOCK"/> is supported</remarks>
		public byte SrbType { get; set; } = 0;
		//internal STORAGE_BUS_TYPE StorageBusType = STORAGE_BUS_TYPE.BusTypeUnknown;
		/// <summary>
		/// The device's LUN/WWN
		/// </summary>
		public string LogicalUnitIdentifier { get; set; } = string.Empty;
		/// <summary>
		/// The device's supported data encryption algorithms
		/// </summary>
		public List<SPTI.LTO.DATA_ENCRYPTION_ALGORITHM> DataEncryptionAlgorithms { get; set; } = [];
		/// <summary>
		/// The device's key wrapping public key
		/// </summary>
		public byte[]? KeyWrapPublicKey { get; set; }
		/// <summary>
		/// The device's wrapped key descriptors
		/// </summary>
		public byte[]? WrappedKeyDescriptors { get; set; }
		/// <summary>
		/// Non-persistent drive state information, including current cartridge information
		/// </summary>
		public TapeDriveState State { get; set; } = new();
		/// <summary>
		/// Value is true if this device's <see cref="SrbType"/> is supported
		/// </summary>
		public bool IsSupported
		{
			get
			{
				return SrbType switch
				{
					(byte)Windows.Win32.PInvoke.SRB_TYPE_SCSI_REQUEST_BLOCK => false,
					(byte)Windows.Win32.PInvoke.SRB_TYPE_STORAGE_REQUEST_BLOCK => true,
					_ => false
				};
			}
		}
	}
}
