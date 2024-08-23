using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SPTI
{
	public partial class LTO
	{
		private static void ClearCachedParitionMamData(Models.TapeDrive tapeDrive)
		{
			tapeDrive.State.CurrentTape = new();
			tapeDrive.State.CurrentTape.MamRawAttributes[0].Clear();
			tapeDrive.State.CurrentTape.PartitionsCapacity[0] = 0;
			tapeDrive.State.CurrentTape.PartitionsCapacityRemaining[0] = 0;
			tapeDrive.State.CurrentTape.MamRawAttributes[1].Clear();
			tapeDrive.State.CurrentTape.PartitionsCapacity[1] = 0;
			tapeDrive.State.CurrentTape.PartitionsCapacityRemaining[1] = 0;
			tapeDrive.State.CurrentTape.MamRawAttributes[2].Clear();
			tapeDrive.State.CurrentTape.PartitionsCapacity[2] = 0;
			tapeDrive.State.CurrentTape.PartitionsCapacityRemaining[2] = 0;
			tapeDrive.State.CurrentTape.MamRawAttributes[3].Clear();
			tapeDrive.State.CurrentTape.PartitionsCapacity[3] = 0;
			tapeDrive.State.CurrentTape.PartitionsCapacityRemaining[3] = 0;
		}

		public static void GetCartridgeMemory(Models.TapeDrive tapeDrive)
		{
			ArgumentNullException.ThrowIfNull(tapeDrive);
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			ClearCachedParitionMamData(tapeDrive);
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateReadAttributeSrb(ref sptwb_ex, Constants.READ_ATTRIBUTE_SERVICE_PARTITION_LIST);
			sptwb_ex.SetCbdValue(8, 0x00);
			sptwb_ex.SetCbdValue(9, 0x00);
			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				Trace.WriteLine("Attributes obtained.");
				using BinaryReader reader = new(new MemoryStream(sptwb_ex.ucDataBuf));
				uint pageLength = ReverseByteOrder(reader.ReadUInt16());
				byte firstPartitionNumber = reader.ReadByte();
				byte partitionCount = reader.ReadByte();
				for (byte i = firstPartitionNumber; i < partitionCount; i++)
				{
					GetCartridgeMemory(tapeDrive, i);
				}
			}
			else if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				_ = WaitForSenseChange(tapeDrive, ref sptwb_ex);
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

		public static void GetCartridgeMemory(Models.TapeDrive tapeDrive, byte partitionNumber)
		{
			ArgumentNullException.ThrowIfNull(tapeDrive);
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateReadAttributeSrb(ref sptwb_ex, Constants.READ_ATTRIBUTE_SERVICE_ATTRIBUTE_VALUES);
			sptwb_ex.SetCbdValue(7, partitionNumber);
			sptwb_ex.SetCbdValue(8, 0x00);
			sptwb_ex.SetCbdValue(9, 0x00);
			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				Trace.WriteLine($"Attributes obtained for partition {partitionNumber}.");
				ParseAttributes(tapeDrive, sptwb_ex, returnedData, partitionNumber);
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

		internal static void ParseAttributes(Models.TapeDrive tapeDrive, NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, uint returnedDataLength, byte partitionNumber)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed || tapeDrive.State.CurrentTape is null)
			{
				return;
			}
			tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].Clear();
			using BinaryReader reader = new(new MemoryStream(sptwb_ex.ucDataBuf));
			uint pageLength = ReverseByteOrder(reader.ReadUInt32());
			while (reader.BaseStream.Position < returnedDataLength - sizeof(uint))
			{
				RawMamAttributeValue currentAttribute = new()
				{
					ID = ReverseByteOrder(reader.ReadUInt16())
				};
				if (currentAttribute.ID <= tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].LastOrDefault()?.ID)
				{
					break;
				}
				byte byte3 = reader.ReadByte();
				currentAttribute.SetFormat((byte)(byte3 & 0b00000011));
				currentAttribute.SetReadOnly((byte)(byte3 >> 7 & 0b00000001));
				ushort attributeLength = ReverseByteOrder(reader.ReadUInt16());
				currentAttribute.SetAttributeLength(attributeLength);
				currentAttribute.RawData = reader.ReadBytes(attributeLength);
				tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].Add(currentAttribute);
			}
			if (tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].Count > 0)
			{
				string barcodeSuffix = "";
				RawMamAttributeValue? attribute = tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].FirstOrDefault(x => x.ID == Constants.MAM_MEDIUM_TYPE);
				byte mediumType = new();
				if (attribute is not null && attribute != default && attribute.RawData is not null)
				{
					mediumType = attribute.RawData[0];
				}
				attribute = tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].FirstOrDefault(x => x.ID == Constants.MAM_MEDIUM_DENSITY_CODE);
				if (attribute is not null && attribute != default && attribute.RawData is not null)
				{
					if (mediumType == 0x00)
					{
						barcodeSuffix = attribute.RawData[0] switch
						{
							0x40 => "L1",
							0x42 => "L2",
							0x44 => "L3",
							0x46 => "L4",
							0x58 => "L5",
							0x5A => "L6",
							0x5C => "L7",
							0x5D => "M8",
							0x5E => "L8",
							0x60 => "L9",
							_ => "XX"
						};
					}
					else if (mediumType == 0x80)
					{
						barcodeSuffix = attribute.RawData[0] switch
						{
							0x44 => "LT",
							0x46 => "LU",
							0x58 => "LV",
							0x5A => "LW",
							0x5C => "LX",
							0x5E => "LY",
							0x60 => "LZ",
							_ => "XX"
						};
					}
				}
				attribute = tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].FirstOrDefault(x => x.ID == Constants.MAM_BARCODE);
				if (attribute is not null && attribute != default && attribute.RawData is not null)
				{
					tapeDrive.State.CurrentTape.Barcode = string.Concat(Encoding.ASCII.GetString(attribute.RawData).TrimEnd(), barcodeSuffix);
				}
				attribute = tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].FirstOrDefault(x => x.ID == Constants.MAM_MAXIMUM_PARTITION_CAPACITY);
				if (attribute is not null && attribute != default && attribute.RawData is not null)
				{
					tapeDrive.State.CurrentTape.PartitionsCapacity[partitionNumber] = ReverseByteOrder(BitConverter.ToUInt64(attribute.RawData));
				}
				attribute = tapeDrive.State.CurrentTape.MamRawAttributes[partitionNumber].FirstOrDefault(x => x.ID == Constants.MAM_REMAINING_PARTITION_CAPACITY);
				if (attribute is not null && attribute != default && attribute.RawData is not null)
				{
					tapeDrive.State.CurrentTape.PartitionsCapacityRemaining[partitionNumber] = ReverseByteOrder(BitConverter.ToUInt64(attribute.RawData));
				}
			}
		}
	}
}
