using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using uk.JohnCook.dotnet.LTOEncryptionManager.SPTI;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Models
{
	public class RawMamAttributeValue
	{
		public ushort ID { get; set; }
		private BitVector32 _byte3;
		public BitVector32 Byte3 => _byte3;
		private byte[]? _rawData;

		private readonly BitVector32.Section _format;
		private readonly BitVector32.Section _reserved1;
		private readonly BitVector32.Section _readOnly;

		public bool IsReadOnly => _byte3[_readOnly] == 1;

		public RawMamAttributeValue()
		{
			_byte3 = new(0);
			_format = BitVector32.CreateSection(1 << 2 - 1);
			_reserved1 = BitVector32.CreateSection(1 << 5 - 1, _format);
			_readOnly = BitVector32.CreateSection(1 << 1 - 1, _reserved1);
		}

		public void SetReadOnly(byte readOnly)
		{
			_byte3[_readOnly] = readOnly;
		}

		public void SetFormat(byte format)
		{
			_byte3[_format] = format;
		}

		public void SetAttributeLength(ushort length)
		{
			_rawData = new byte[length];
		}

		public uint Format => _byte3[_format] switch
		{
			0b00 => Constants.MAM_FORMAT_BINARY,
			0b01 => Constants.MAM_FORMAT_ASCII,
			0b10 => Constants.MAM_FORMAT_TEXT,
			0b11 => Constants.MAM_FORMAT_RESERVED,
			_ => Constants.MAM_FORMAT_INVALID
		};

		public byte[]? GetRawData()
		{
			return _rawData;
		}

		public void SetRawData(byte[]? value)
		{
			_rawData = value;
		}
	}

	public class TapeDriveTape
	{
		public string? Barcode { get; set; }
		public bool? IsCompressed { get; set; }
		public bool? IsEncrypted { get; set; }
		public string? AuthKadString { get; set; }
		public string? UnauthKadString { get; set; }
		public string? KadString
		{
			get
			{
				return AuthKadString == null ? null : string.Concat(AuthKadString, UnauthKadString);
			}
		}
		public long? FirstEncryptedBlock { get; set; }
		public long? FirstUnencryptedBlock { get; set; }
		public byte? AlgorithmIndex { get; set; }
		public string? ApplicationName { get; set; }
		public bool? IsLtfsFormatted
		{
			get
			{
				return ApplicationName?.StartsWith("LTFS ", StringComparison.Ordinal);
			}
		}
		public string? PartitionTextLabel { get; set; }
		public byte? VolumeLocked { get; set; }

		public Collection<Collection<RawMamAttributeValue>> MamRawAttributes { get; } = [[], [], [], []];
		public Collection<ulong> PartitionsCapacity { get; } = [];
		public Collection<ulong> PartitionsCapacityRemaining { get; } = [];
	}

	public class ScsciStatusChangedEventArgs(int status) : EventArgs
	{
		public int Status { get; init; } = status;
	}

	public class TapeDriveState
	{
		public event EventHandler<ScsciStatusChangedEventArgs>? ScsiStatusChanged;
		public event EventHandler<TapeDriveErrorEventArgs>? ErrorMessageChanged;
		public DateTime? LastExceptionTime { get; set; }
		public Exception? LastException { get; set; }
		public DateTime? LastHResultTime { get; set; }
		public int LastHResult { get; set; }
		public DateTime? LastScsiStatusTime { get; set; }
		private int _scsiStatus;
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
				ScsiStatusChanged?.Invoke(this, new(value));
			}
		}
		public DateTime? LastSenseInfoTime { get; set; }
		private byte[]? _lastSenseInfo;
		public byte[]? GetLastSenseInfo()
		{
			return _lastSenseInfo;
		}
		public void SetLastSenseInfo(byte[]? value)
		{
			_lastSenseInfo = value;
		}

		public DateTime? LastErrorMessageTime { get; set; }
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
		public TapeDriveTape? CurrentTape { get; set; }
	}

	/// <summary>
	/// An LTO Tape device
	/// </summary>
	public class TapeDrive
	{
		/// <summary>
		/// The <see cref="Guid"/> for a tape device interface
		/// </summary>
		static readonly Guid GUID_DEVINTERFACE_TAPE = new("{53F5630B-B6BF-11D0-94F2-00A0C91EFB8B}");
		/// <summary>
		/// The device's identifier
		/// </summary>
		public string DeviceId { get; set; } = string.Empty;
		/// <summary>
		/// The full file path for opening the device
		/// </summary>
		public string Path => string.Concat(@"\\?\", DeviceId.Replace("\\", "#", StringComparison.Ordinal), "#{", GUID_DEVINTERFACE_TAPE.ToString(), "}");
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
		public uint AlignmentMask { get; set; }
		/// <summary>
		/// The device's SCSI Request Block (SRB) type
		/// </summary>
		/// <remarks>Only <see cref="Windows.Win32.PInvoke.SRB_TYPE_STORAGE_REQUEST_BLOCK"/> is supported</remarks>
		public byte SrbType { get; set; }
		//internal STORAGE_BUS_TYPE StorageBusType = STORAGE_BUS_TYPE.BusTypeUnknown;
		/// <summary>
		/// The device's LUN/WWN
		/// </summary>
		public string LogicalUnitIdentifier { get; set; } = string.Empty;
		/// <summary>
		/// The device's supported data encryption algorithms
		/// </summary>
		internal Collection<SPTI.LTO.DATA_ENCRYPTION_ALGORITHM> DataEncryptionAlgorithms { get; set; } = [];
		/// <summary>
		/// The device's key wrapping public key
		/// </summary>
		private byte[] _keyWrapPublicKey = [];
		public byte[] GetKeyWrapPublicKey()
		{
			return _keyWrapPublicKey;
		}
		public void SetKeyWrapPublicKey(byte[] value)
		{
			_keyWrapPublicKey = value;
		}
		/// <summary>
		/// The device's wrapped key descriptors
		/// </summary>
		private byte[] _wrappedKeyDescriptors = [];
		public byte[] GetWrappedKeyDescriptors()
		{
			return _wrappedKeyDescriptors;
		}
		public void SetWrappedKeyDescriptors(byte[] value)
		{
			_wrappedKeyDescriptors = value;
		}

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
