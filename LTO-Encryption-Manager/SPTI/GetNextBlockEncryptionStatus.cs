using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SPTI
{
	public partial class LTO
	{
		public static void GetNextBlockEncryptionStatus(Models.TapeDrive tapeDrive)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex = new();
			sptwb_ex.Init();
			uint length = CreateSecurityProtocolInSrb(ref sptwb_ex, Constants.SECURITY_PROTOCOL_TAPE, Constants.SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS);
			bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
			if (ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
			{
				Trace.WriteLine("Attributes obtained.");
				ParseNextBlockEncryptionAttributes(tapeDrive, sptwb_ex, returnedData);
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

		//internal static void RewindTape(Models.TapeDrive tapeDrive, NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex)
		//{
		//	uint length = ResetSrbIn(ref sptwb_ex, Constants.SCSIOP_REWIND);
		//	bool ok = TrySendSrb(tapeDrive, ref sptwb_ex, length, out uint returnedData, out int hresult);
		//	if (ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
		//	{
		//		Trace.WriteLine("Rewind complete.");
		//	}
		//	else if (!ok && sptwb_ex.spt.ScsiStatus == Constants.SCSISTAT_GOOD)
		//	{
		//		ok = WaitForSenseChange(tapeDrive, ref sptwb_ex);
		//	}
		//	else if (!ok || sptwb_ex.spt.ScsiStatus != Constants.SCSISTAT_GOOD)
		//	{
		//		int error = Marshal.GetLastWin32Error();
		//		Marshal.ThrowExceptionForHR(error);
		//	}
		//	else
		//	{
		//		Trace.WriteLine("Unreachable?");
		//	}
		//}

		internal static void ParseNextBlockEncryptionAttributes(Models.TapeDrive tapeDrive, NATIVE_SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex, uint returnedDataLength)
		{
			if (tapeDrive.Handle is null || tapeDrive.Handle.IsInvalid || tapeDrive.Handle.IsClosed)
			{
				return;
			}
			if (tapeDrive.State.CurrentTape is null)
			{
				tapeDrive.State.CurrentTape = new();
			}

			using BinaryReader reader = new(new MemoryStream(sptwb_ex.ucDataBuf));
			ushort pageCode = ReverseByteOrder(reader.ReadUInt16());
			ushort pageLength = ReverseByteOrder(reader.ReadUInt16());
			ulong blockNumber = ReverseByteOrder(reader.ReadUInt64());
			byte byte13 = reader.ReadByte();
			byte encryptionStatus = (byte)(byte13 & 0b00001111);
			byte compressionStatus = (byte)((byte13 >> 8) & 0b00001111);
			tapeDrive.State.CurrentTape.IsEncrypted = encryptionStatus switch
			{
				0x00 => null,
				0x01 => null,
				0x02 => null,
				0x03 => false,
				0x04 => true,
				0x05 => true,
				0x06 => true,
				_ => null
			};
			if (tapeDrive.State.CurrentTape.IsEncrypted == false)
			{
				tapeDrive.State.LastErrorMessage = "The next block is not encrypted";
				return;
			}
			else if (tapeDrive.State.CurrentTape.IsEncrypted == null)
			{
				tapeDrive.State.LastErrorMessage = "The next block may or may not be encrypted";
				return;
			}
			tapeDrive.State.CurrentTape.AlgorithmIndex = reader.ReadByte();
			byte byte15 = reader.ReadByte();
			byte nextBlockKadFormat = reader.ReadByte();
			List<PLAIN_KEY_DESCRIPTOR> descriptors = [];
			while (reader.BaseStream.Position < pageLength + 4)
			{
				PLAIN_KEY_DESCRIPTOR kad = new()
				{
					Type = reader.ReadByte()
				};
				if (descriptors.Count > 0 && kad.Type <= descriptors.LastOrDefault().Type)
				{
					break;
				}
				byte byte2 = reader.ReadByte();
				kad.SetAuthenticated((byte)(byte2 & 0b00000111));
				kad.Length = ReverseByteOrder(reader.ReadUInt16());
				kad.Descriptor = reader.ReadBytes(kad.Length);
				descriptors.Add(kad);
			}
			if (descriptors.Count > 0 && nextBlockKadFormat == Constants.SPOUT_TAPE_KAD_FORMAT_ASCII)
			{
				PLAIN_KEY_DESCRIPTOR? descriptorType = descriptors.FirstOrDefault(x => x.Type == Constants.SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH);
				if (descriptorType is not null && descriptorType?.Descriptor is not null)
				{
					tapeDrive.State.CurrentTape.AuthKadString = Encoding.ASCII.GetString(descriptorType.Value.Descriptor).TrimEnd();
				}
				descriptorType = descriptors.FirstOrDefault(x => x.Type == Constants.SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH);
				if (descriptorType is not null && descriptorType?.Descriptor is not null)
				{
					tapeDrive.State.CurrentTape.UnauthKadString = Encoding.ASCII.GetString(descriptorType.Value.Descriptor).TrimEnd();
				}
			}
		}
	}
}