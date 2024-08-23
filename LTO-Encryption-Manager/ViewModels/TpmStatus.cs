/*
 * Copyright (c) 2013 Microsoft Corporation
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Tpm2Lib;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Commands;

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

                _ = tpm.GetCapability(Cap.Algs, 0, 1000, out ICapabilitiesUnion caps);
                AlgPropertyArray algsx = (AlgPropertyArray)caps;

                //Trace.WriteLine("Supported algorithms:");
                foreach (AlgProperty? alg in algsx.algProperties)
                {
                    SupportedAlgo.Add(alg.alg);
                    //Trace.WriteLine($"  {alg.alg}");
                }
                /*
                Trace.WriteLine("Supported commands:");
                _ = tpm.GetCapability(Cap.TpmProperties, (uint)Pt.TotalCommands, 1, out caps);
                _ = tpm.GetCapability(Cap.Commands, (uint)TpmCc.First, TpmCc.Last - TpmCc.First + 1, out caps);

                CcaArray? commands = (CcaArray)caps;
                List<TpmCc> implementedCc = new();
                foreach (CcAttr attr in commands.commandAttributes)
                {
                    TpmCc commandCode = (TpmCc)((uint)attr & 0x0000FFFFU);
                    implementedCc.Add(commandCode);
                    Trace.WriteLine($"  {commandCode}");
                }

                Trace.WriteLine("Commands from spec not implemented:");
                foreach (object? cc in Enum.GetValues(typeof(TpmCc)))
                {
                    if (!implementedCc.Contains((TpmCc)cc))
                    {
                        Trace.WriteLine($"  {cc}");
                    }
                }
                */
                //
                // Read PCR attributes. Cap.Pcrs returns the list of PCRs which are supported
                // in different PCR banks. The PCR banks are identified by the hash algorithm
                // used to extend values into the PCRs of this bank.
                //
                _ = tpm.GetCapability(Cap.Pcrs, 0, 255, out caps);
                PcrSelection[] pcrs = ((PcrSelectionArray)caps).pcrSelections;

                //Trace.WriteLine(string.Empty);
                //Trace.WriteLine("Available PCR banks:");
                foreach (PcrSelection pcrBank in pcrs)
                {
                    HasPcrBankAlgo.Add(pcrBank.hash);
                    StringBuilder? sb = new();
                    _ = sb.Append(CultureInfo.InvariantCulture, $"PCR bank for algorithm {pcrBank.hash} has registers at index:");
                    _ = sb.AppendLine();
                    foreach (uint selectedPcr in pcrBank.GetSelectedPcrs())
                    {
                        _ = sb.Append(CultureInfo.InvariantCulture, $"{selectedPcr},");
                    }
                    //Trace.WriteLine(sb);
                }

                //
                // Read PCR attributes. Cap.PcrProperties checks for certain properties of each PCR register.
                //
                _ = tpm.GetCapability(Cap.PcrProperties, 0, 255, out caps);

                //Trace.WriteLine(string.Empty);
                //Trace.WriteLine("PCR attributes:");
                TaggedPcrSelect[] pcrProperties = ((TaggedPcrPropertyArray)caps).pcrProperty;
                foreach (TaggedPcrSelect pcrProperty in pcrProperties)
                {
                    if (pcrProperty.tag == PtPcr.None)
                    {
                        continue;
                    }

                    uint pcrIndex = 0;
                    StringBuilder? sb = new();
                    _ = sb.Append(CultureInfo.InvariantCulture, $"PCR property {pcrProperty.tag} supported by these registers: ");
                    _ = sb.AppendLine();
                    foreach (byte pcrBitmap in pcrProperty.pcrSelect)
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
                    //Trace.WriteLine(sb);
                }
                //Trace.WriteLine(string.Empty);

                //Trace.WriteLine("\nPCR sample started.");
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
                tpm.Dispose();
                Completed?.Invoke(this, new(true));
            }
            catch (Exception e)
            {
                Trace.WriteLine($"Exception occurred: {e.Message}");
                Completed?.Invoke(this, new(true));
            }
        }
    }
}
