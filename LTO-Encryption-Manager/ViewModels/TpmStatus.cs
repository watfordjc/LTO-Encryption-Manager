/*
 * Copyright (c) 2013 Microsoft Corporation
 */

using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Tpm2Lib;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels
{
	public class TpmInitialisedEventArgs(bool hasCompleted) : EventArgs
	{
		public bool HasCompleted { get; init; } = hasCompleted;
	}

	public class TpmStatus : ViewModelBase
	{
		public bool HasTpm { get; private set; }
		public Collection<TpmAlgId> SupportedAlgo { get; private set; } = [];
		public Collection<TpmAlgId> HasPcrBankAlgo { get; private set; } = [];
		public event EventHandler<TpmInitialisedEventArgs>? Completed;

		public TpmStatus()
		{

		}

		public void Begin()
		{
			using Tpm2Device tpmDevice = new TbsDevice();
			try
			{
				//
				// Connect to the TPM device. This function actually establishes the
				// connection.
				//
				tpmDevice.Connect();
				//
				// Pass the device object used for communication to the TPM 2.0 object
				// which provides the command interface.
				//
				using Tpm2 tpm = new(tpmDevice);
				HasTpm = true;

				_ = tpm.GetCapability(Cap.Algs, 0, 1000, out ICapabilitiesUnion capabilities);
				if (capabilities is not AlgPropertyArray algPropertyArray)
				{
					Completed?.Invoke(this, new(true));
					return;
				}
				foreach (AlgProperty algProperty in algPropertyArray.algProperties)
				{
					SupportedAlgo.Add(algProperty.alg);
				}

				//
				// Read PCR attributes. Cap.Pcrs returns the list of PCRs which are supported
				// in different PCR banks. The PCR banks are identified by the hash algorithm
				// used to extend values into the PCRs of this bank.
				//
				_ = tpm.GetCapability(Cap.Pcrs, 0, 255, out capabilities);
				if (capabilities is not PcrSelectionArray pcrSelectionArray)
				{
					Completed?.Invoke(this, new(true));
					return;
				}
				foreach (PcrSelection pcrSelection in pcrSelectionArray.pcrSelections)
				{
					HasPcrBankAlgo.Add(pcrSelection.hash);
				}

				//
				// Read PCR attributes. Cap.PcrProperties checks for certain properties of each PCR register.
				//
				_ = tpm.GetCapability(Cap.PcrProperties, 0, 255, out capabilities);
				if (capabilities is not TaggedPcrPropertyArray taggedPcrPropertyArray)
				{
					Completed?.Invoke(this, new(true));
					return;
				}
				foreach (TaggedPcrSelect taggedPcrSelect in taggedPcrPropertyArray.pcrProperty)
				{
					if (taggedPcrSelect.tag == PtPcr.None)
					{
						continue;
					}

					uint pcrIndex = 0;
					StringBuilder? sb = new();
					_ = sb.Append(CultureInfo.InvariantCulture, $"PCR property {taggedPcrSelect.tag} supported by these registers: ");
					_ = sb.AppendLine();
					foreach (byte pcrBitmap in taggedPcrSelect.pcrSelect)
					{
						for (int i = 0; i < 8; i++)
						{
							if ((pcrBitmap & (1 << i)) != 0)
							{
								_ = sb.Append(CultureInfo.InvariantCulture, $"{pcrIndex},");
							}
							pcrIndex++;
						}
					}
				}

				//
				// Read the value of the SHA256 PCR 7 and 11
				//
				uint[] pcrsToSelect = [7, 11];
				PcrSelection[]? valuesToRead =
					[
					new PcrSelection(TpmAlgId.Sha256, pcrsToSelect)
					];
				_ = tpm.PcrRead(valuesToRead, out PcrSelection[] valsRead, out Tpm2bDigest[] values);

				//
				// Check that what we read is what we asked for (the TPM does not 
				// guarantee this)
				//
				if (valsRead[0] != valuesToRead[0])
				{
					Trace.WriteLine("Unexpected PCR-set");
				}

				//
				// Print out PCRs
				//
				for (int i = 0; i < values.Length; i++)
				{
					TpmHash pcrHash = new(TpmAlgId.Sha256, values[i].buffer);
					//Trace.WriteLine($"PCR{pcrsToSelect[i]}: {BitConverter.ToString(pcrHash.HashData).Replace("-", "").ToLower(CultureInfo.InvariantCulture)}");
				}

				//
				// Clean up.
				//
				Completed?.Invoke(this, new(true));
			}
			// StringBuilder.AppendLine (ArgumentOutOfRangeException)
			catch (Exception ex) when
			(ex is ArgumentOutOfRangeException)
			{
				Trace.WriteLine($"Exception occurred: {ex.Message}");
				Completed?.Invoke(this, new(true));
			}
		}
	}
}
