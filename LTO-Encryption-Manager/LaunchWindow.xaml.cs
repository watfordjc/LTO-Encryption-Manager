using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Media;
using System.Windows.Threading;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Windows.Win32.Storage.FileSystem;
using Microsoft.Win32.SafeHandles;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.SPTI;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Windows.Win32.Foundation;

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
	/// <summary>
	/// Interaction logic for LaunchWindow.xaml
	/// </summary>
	public sealed partial class LaunchWindow : System.Windows.Window
	{
		private bool _secureBootEnabled;
		private bool SecureBootEnabled { get { return _secureBootEnabled; } set { _secureBootEnabled = value; lblSecureBootStatus.Content = string.Format("Secure Boot Enabled: {0}", value ? "Yes" : "No"); } }
		private TpmStatus? TpmStatus { get; set; }
		private bool _tpmSupported;
		private bool TpmSupported { get { return _tpmSupported; } set { _tpmSupported = value; lblTpmStatus.Content = string.Format("Suitable TPM 2.0 Available: {0}", value ? "Yes" : "No"); } }
		private string _error = string.Empty;
		private string Error { get { return _error; } set { _error = value; statusbarStatus.Content = _error == string.Empty ? "No recent errors" : $"{value}"; } }
		private string CurrentAccountDataFile { get; set; } = string.Empty;
		private Slip21NodeEncrypted? currentAccountSlip21Node;
		KeyAssociatedData? kad = null;
		private readonly List<string> GlobalFingerprints = new();
		private readonly List<string> AccountFingerprints = new();
		private List<TapeDrive> TapeDrives { get; init; } = new();

		public LaunchWindow()
		{
			InitializeComponent();
			Error = string.Empty;
			SecureBootEnabled = SecureBoot.IsEnabled();
			btnCreateAccountNewRecoverySeed.IsEnabled = _secureBootEnabled;
			btnCreateAccountExistingRecoverySeed.IsEnabled = _secureBootEnabled;
			TpmStatus = new();
			TpmStatus.Completed += TpmStatus_Completed;
			TpmStatus.Begin();
			Window.DataContext = this;
			btnCreateRsaKey.Click += BtnCreateRsaKey_Click;
			cbGlobalFingerprints.SelectionChanged += CbGlobalFingerprints_SelectionChanged;
			cbAccountFingerprints.SelectionChanged += CbAccountFingerprints_SelectionChanged;
			btnCreateAccountNewRecoverySeed.Click += BtnCreateAccountNewRecoverySeed_Click;
			btnCreateAccountExistingRecoverySeed.Click += BtnCreateAccountExistingRecoverySeed_Click;
			btnTestAccount.Click += BtnTestAccount_Click;
			cbTapeDrives.SelectionChanged += CbTapeDrives_SelectionChanged;
			btnDetectTape.Click += BtnDetectTape_Click;
			btnRescanDrives.Click += BtnRescanDrives_Click;
			btnCalculateKAD.Click += BtnCalculateKAD_Click;
			btnEnableDriveEncryption.Click += BtnEnableDriveEncryption_Click;
			btnDisableDriveEncryption.Click += BtnDisableDriveEncryption_Click;
			tbTapeKAD.TextChanged += TbTapeKAD_TextChanged;
		}

		private void BtnRescanDrives_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			EnumerateTapeDrives();
		}

		private void TbTapeKAD_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
		{
			if (cbTapeDrives.SelectedIndex == -1 || TapeDrives.Count <= cbTapeDrives.SelectedIndex || TapeDrives[cbTapeDrives.SelectedIndex] is null)
			{
				Error = "Error: No tape drive selected.";
				return;
			}
			TapeDrive currentDrive = TapeDrives[cbTapeDrives.SelectedIndex];
			if (!string.IsNullOrEmpty(tbTapeKAD.Text))
			{
				string[] asteriskSplits = tbTapeKAD.Text.Split('*');
				if (asteriskSplits.Length > 1)
				{
					tbTapeLabel.Text = asteriskSplits[0];
					tbTapeKeyRollovers.Text = asteriskSplits[1][2].ToString();
				}
				else
				{
					tbTapeLabel.Text = currentDrive.State.CurrentTape?.Barcode;
					tbTapeKAD.Text = currentDrive.State.CurrentTape?.KadString;
				}
			}
			else
			{
				tbTapeLabel.Text = currentDrive.State.CurrentTape?.Barcode;
				tbTapeKAD.Text = currentDrive.State.CurrentTape?.KadString;
			}
		}

		private void BtnDetectTape_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			if (cbTapeDrives.SelectedIndex == -1 || TapeDrives.Count <= cbTapeDrives.SelectedIndex || TapeDrives[cbTapeDrives.SelectedIndex] is null)
			{
				Error = "Error: No tape drive selected.";
				return;
			}
			btnDetectTape.IsEnabled = false;
			tbTapeLabel.Text = string.Empty;
			tbTapeKeyRollovers.Text = string.Empty;
			tbTapeKAD.Text = string.Empty;
			tbDriveKAD.Text = string.Empty;
			TapeDrive currentDrive = TapeDrives[cbTapeDrives.SelectedIndex];
			currentDrive.Handle = Windows.Win32.PInvoke.CreateFile(currentDrive.Path, (uint)(GENERIC_ACCESS_RIGHTS.GENERIC_WRITE | GENERIC_ACCESS_RIGHTS.GENERIC_READ), FILE_SHARE_MODE.FILE_SHARE_READ, null, FILE_CREATION_DISPOSITION.OPEN_EXISTING, 0, null);
			SPTI.LTO.GetCartridgeMemory(TapeDrives[cbTapeDrives.SelectedIndex]);
			SPTI.LTO.GetNextBlockEncryptionStatus(TapeDrives[cbTapeDrives.SelectedIndex]);
			currentDrive.Handle.Close();
			tbTapeLabel.Text = currentDrive.State.CurrentTape?.Barcode;
			tbTapeKAD.Text = currentDrive.State.CurrentTape?.KadString;
			tbLtfsDataCapacity.Text = (currentDrive.State.CurrentTape?.PartitionsCapacity[1] / 1000).ToString();
			tbLtfsDataCapacityRemaining.Text = (currentDrive?.State.CurrentTape?.PartitionsCapacityRemaining[1] / 1000).ToString();
			btnDetectTape.IsEnabled = true;
		}

		private void TpmStatus_Completed(object? sender, bool e)
		{
			if (sender is TpmStatus tpmStatus)
			{
				TpmSupported =
					SecureBootEnabled &&
					tpmStatus.HasTpm &&
					tpmStatus.HasPcrBankAlgo.Contains(Tpm2Lib.TpmAlgId.Sha256) &&
					tpmStatus.SupportedAlgo.Contains(Tpm2Lib.TpmAlgId.Rsa) &&
					tpmStatus.SupportedAlgo.Contains(Tpm2Lib.TpmAlgId.Aes);
			}
			else
			{
				TpmSupported = false;
				return;
			}
			if (!TryEnumerateGlobalFingerprints(GlobalFingerprints, AccountFingerprints, out Exception? exception))
			{
				Error = $"Account listing error: {exception.Message}";
			}
			EnumerateTapeDrives();
			EnableHpeLtfsTools();
		}

		private void EnumerateTapeDrives()
		{
			btnRescanDrives.IsEnabled = false;
			TapeDrives.Clear();
			try
			{
				string Namespace = @"root\cimv2";
				string ComputerName = "localhost";
				using DComSessionOptions cimSessionOptions = new()
				{
					Timeout = TimeSpan.FromSeconds(30)
				};
				using CimSession cimSession = CimSession.Create(ComputerName, cimSessionOptions);
				IEnumerable<CimInstance> cimInstances = cimSession.QueryInstances(Namespace, "WQL", @"SELECT * FROM Win32_TapeDrive");
				foreach (CimInstance cimInstance in cimInstances)
				{
					string? deviceId = cimInstance.CimInstanceProperties["DeviceID"].Value.ToString()?.ToLowerInvariant().TrimEnd();
					string? caption = cimInstance.CimInstanceProperties["Caption"].Value.ToString()?.TrimEnd();
					if (deviceId == null)
					{
						continue;
					}
					TapeDrive currentDrive = new();
					currentDrive.State.ErrorMessageChanged += CurrentDriveErrorMessageChanged;
					try
					{
						currentDrive.DeviceId = deviceId;
						currentDrive.Caption = caption ?? string.Empty;
						cimInstance.Dispose();
						Error = $"Obtaining drive information for \"{currentDrive.Caption}\"...";
						currentDrive.Handle = Windows.Win32.PInvoke.CreateFile(currentDrive.Path, (uint)(GENERIC_ACCESS_RIGHTS.GENERIC_WRITE | GENERIC_ACCESS_RIGHTS.GENERIC_READ), FILE_SHARE_MODE.FILE_SHARE_READ, null, FILE_CREATION_DISPOSITION.OPEN_EXISTING, 0, null);
						SPTI.LTO.GetTapeDriveInformation(currentDrive);
						SPTI.LTO.GetTapeDriveIdentifiers(currentDrive);
						SPTI.LTO.GetTapeDriveDataEncryptionCapabilities(currentDrive);
						SPTI.LTO.GetTapeDriveKeyWrapKey(currentDrive);
						currentDrive.Handle.Close();
					}
					finally
					{
						currentDrive.State.ErrorMessageChanged -= CurrentDriveErrorMessageChanged;
					}
					Error = currentDrive.State.DisplayLastErrorMessage;
					TapeDrives.Add(currentDrive);
				}
				if (cbTapeDrives.SelectedIndex >= 0)
				{
					TapeDrives[cbTapeDrives.SelectedIndex].State.ErrorMessageChanged -= CurrentDriveErrorMessageChanged;
				}
				cbTapeDrives.ItemsSource = TapeDrives;
				if (cbTapeDrives.Items.Count == 1)
				{
					cbTapeDrives.SelectedIndex = 0;
					TapeDriveSelected(TapeDrives[0]);
				}
				if (cbTapeDrives.Items.Count > 0)
				{
					btnEnableDriveEncryption.IsEnabled = true;
					btnDisableDriveEncryption.IsEnabled = true;
				}
				btnRescanDrives.IsEnabled = true;
			}
			catch (Exception ex)
			{
				Error = ex.Message;
			}
		}

		private bool TryEnumerateGlobalFingerprints(List<string> globalFingerprints, List<string> accountFingerprints, [NotNullWhen(false)] out Exception? exception)
		{
			exception = null;
			string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			globalFingerprints.Clear();
			accountFingerprints.Clear();
			try
			{
				string accountDirectoriesBase = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts");
				string[] globalFingerprintDirectories = Directory.GetDirectories(accountDirectoriesBase, "*", SearchOption.TopDirectoryOnly);
				foreach (string dir in globalFingerprintDirectories)
				{
					if (Directory.Exists(dir))
					{
						DirectoryInfo dirInfo = new(dir);
						globalFingerprints.Add(Encoding.UTF8.GetString(Convert.FromHexString(dirInfo.Name)));
					}
				}

			}
			catch (Exception ex)
			{
				exception = ex;
				return false;
			}

			OnEnumerateGlobalFingerprintsCompleted(accountFingerprints, out exception);
			return true;
		}

		private void OnEnumerateGlobalFingerprintsCompleted(List<string> accountFingerprints, out Exception? exception)
		{
			exception = null;

			cbGlobalFingerprints.ItemsSource = GlobalFingerprints;
			if (GlobalFingerprints.Count != 1)
			{
				AccountFingerprints.Clear();
				cbAccountFingerprints.ItemsSource = AccountFingerprints;
				return;
			}

			cbGlobalFingerprints.SelectedIndex = 0;
			if (TryEnumerateAccountFingerprints(GlobalFingerprints[0], ref accountFingerprints, out exception))
			{

			}
			else
			{
				cbAccountFingerprints.ItemsSource = accountFingerprints;
				return;
			}
		}

		private bool TryEnumerateAccountFingerprints(string globalFingerprint, ref List<string> accountFingerprints, [NotNullWhen(false)] out Exception? exception)
		{
			exception = null;
			string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			try
			{
				string accountDirectoriesBase = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts", Convert.ToHexString(Encoding.UTF8.GetBytes(globalFingerprint)));
				string[] accountFingerprintFiles = Directory.GetFiles(accountDirectoriesBase, "*.blob", SearchOption.TopDirectoryOnly);
				accountFingerprints.Clear();
				foreach (string file in accountFingerprintFiles)
				{
					if (File.Exists(file))
					{
						FileInfo fileInfo = new(file);
						accountFingerprints.Add(Encoding.UTF8.GetString(Convert.FromHexString(fileInfo.Name.Split('.')[0])));
					}
				}
				OnAccountEnumerationCompleted();
				return true;
			}
			catch (Exception ex)
			{
				exception = ex;
				return false;
			}
		}

		private void OnAccountEnumerationCompleted()
		{
			cbAccountFingerprints.ItemsSource = AccountFingerprints;
			if (AccountFingerprints.Count == 1)
			{
				cbAccountFingerprints.SelectedIndex = 0;
				UseAccount(AccountFingerprints[0]);
			}
			else
			{
				cbAccountFingerprints.SelectedIndex = -1;
			}
		}

		private void UseAccount(string accountFingerprint)
		{
			if (cbGlobalFingerprints.SelectedIndex == -1 || cbGlobalFingerprints.SelectedItem is not string globalFingerprint)
			{
				return;
			}
			string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			try
			{
				string fileName = Convert.ToHexString(Encoding.UTF8.GetBytes(accountFingerprint)) + ".blob";
				string thisAppDataFile = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts", Convert.ToHexString(Encoding.UTF8.GetBytes(globalFingerprint)), fileName);
				btnTestAccount.IsEnabled = File.Exists(thisAppDataFile);
				CurrentAccountDataFile = thisAppDataFile;
				Error = string.Empty;
				VerifyCurrentAccount(false);
			}
			catch (Exception ex)
			{
				Error = $"Account listing error: {ex.Message}";
			}
		}

		private void VerifyCurrentAccount(bool verifyDecryptionKey)
		{
			using StreamReader streamReader = new(CurrentAccountDataFile, Encoding.UTF8, true, 4096);
			string nodeData = streamReader.ReadToEnd();
			streamReader.Close();

			string[] nodeDataSigSplit = nodeData.Split('\x001E');
			string[] nodeDataSplit = nodeDataSigSplit[0].Split('\x001F');

			currentAccountSlip21Node = new(nodeDataSplit[0], nodeDataSplit[1], nodeDataSplit[2]);
			currentAccountSlip21Node.GlobalFingerprint = nodeDataSplit[3];
			currentAccountSlip21Node.AccountFingerprint = nodeDataSplit[4];
			currentAccountSlip21Node.RSASignature = nodeDataSigSplit[1];

			bool signatureValid = false;
			List<string> keyNames = new();
			keyNames.Add("LTO Encryption Manager account protection");
			RSACng? currentRsaKey = null;
			foreach (string keyName in keyNames)
			{
				if (!Utils.PKI.TryGetRsaKeyByName(keyName, out currentRsaKey))
				{
					continue;
				}
				try
				{
					signatureValid = currentRsaKey.VerifyData(Encoding.UTF8.GetBytes(currentAccountSlip21Node.SignablePart), Convert.FromHexString(currentAccountSlip21Node.RSASignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
				}
				catch (Exception)
				{
					continue;
				}
				if (signatureValid)
				{
					break;
				}
				currentRsaKey.Dispose();
				currentRsaKey = null;
			}
			if (!signatureValid)
			{
				Error = "Account data validation error: Unable to find keypair.";
				btnTestAccount.IsEnabled = true;
				return;
			}
			else if (signatureValid && currentRsaKey?.Key.KeyName?.Equals(keyNames[0]) == false)
			{
				Error = "Account data validation warning: Account file needs upgrading";
				btnTestAccount.IsEnabled = true;
				AsnEncodedData asnEncodedData = new("1.2.840.113549.1.1.1", currentRsaKey.ExportRSAPublicKey());
				tbDriveKAD.Text = Convert.ToHexString(asnEncodedData.RawData);
				return;
			}

			using X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
			my.Open(OpenFlags.ReadOnly);
			if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate))
			{
				Error = $"Certificate retrieval/creation error";
				return;
			}

			RSACng? rsaKey = null;
			RSACng? rsaPubKey = null;
			void Cleanup()
			{
				rsaKey?.Dispose();
				rsaPubKey?.Dispose();
				tpmCertificate?.Dispose();
			}
			try
			{
				rsaKey = (RSACng?)tpmCertificate?.GetRSAPrivateKey();
				rsaPubKey = (RSACng?)tpmCertificate?.GetRSAPublicKey();
			}
			catch (Exception)
			{
				Cleanup();
			}
			if (tpmCertificate?.HasPrivateKey == false || rsaKey is null || rsaPubKey is null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
			{
				Cleanup();
				return;
			}

			try
			{
				signatureValid = rsaPubKey.VerifyData(Encoding.UTF8.GetBytes(currentAccountSlip21Node.SignablePart), Convert.FromHexString(currentAccountSlip21Node.RSASignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
			}
			catch (Exception)
			{
				Cleanup();
				return;
			}
			if (!signatureValid || !verifyDecryptionKey)
			{
				my.Close();
				Cleanup();
				return;
			}
			else if (signatureValid && verifyDecryptionKey)
			{
				byte[] nodeBytes = new byte[64];
				Array.Clear(nodeBytes, 0, 64);
				try
				{
					statusbarStatus.Content = "Testing account key decryption...";
					byte[] nodeLeft = rsaKey.Decrypt(Convert.FromHexString(currentAccountSlip21Node.EncryptedLeftHex), RSAEncryptionPadding.Pkcs1);
					Array.Copy(nodeLeft, 0, nodeBytes, 0, 32);
					Slip21Node accountNode = new(nodeBytes, nodeDataSplit[2], nodeDataSplit[1]);
					Slip21ValidationNode accountValidationNode = new(accountNode);
					accountValidationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
					{
						if (e)
						{
							string accountValidationFingerprint = accountValidationNode.Fingerprint ?? string.Empty;
							bool accountFingerprintMatches = accountValidationFingerprint != string.Empty && accountValidationFingerprint == nodeDataSplit[4];
							//Trace.WriteLine(string.Format("RSA-signed account node fingerprint: {0}. Fingerprint derived from decrypted account derivation key: {1}. TPM-backed keypair {2} validation check. Global node fingerprint: {3}", nodeDataSplit[4], accountValidationFingerprint, accountFingerprintMatches ? "passes" : "fails", nodeDataSplit[3]));
							statusbarStatus.Content = string.Format("Account Test Result: TPM-backed keypair {0} validation check.", accountFingerprintMatches ? "passes" : "fails");
							btnTestAccount.IsEnabled = true;
						}
					});
					statusbarStatus.Content = "Calculating account fingerprint...";
					accountValidationNode.CalculateFingerprint();
				}
				catch (Exception ex)
				{
					Error = $"Decryption Error: {ex.Message}";
					btnTestAccount.IsEnabled = true;
				}
			}
		}

		private void EnableHpeLtfsTools()
		{
			string hpeLtfsCartridgeBrowserLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Cartridge Browser.lnk";
			if (File.Exists(hpeLtfsCartridgeBrowserLink))
			{
				btnStartLtfsCartridgeBrowser.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsCartridgeBrowserLink);
				btnStartLtfsCartridgeBrowser.IsEnabled = true;
			}
			string hpeLtfsCheckWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Check Wizard.lnk";
			if (File.Exists(hpeLtfsCheckWizardLink))
			{
				btnStartLtfsCheckWizard.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsCheckWizardLink);
				btnStartLtfsCheckWizard.IsEnabled = true;
			}
			string hpeLtfsConfiguratorLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Configurator.lnk";
			if (File.Exists(hpeLtfsConfiguratorLink))
			{
				btnStartLtfsConfigurator.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsConfiguratorLink);
				btnStartLtfsConfigurator.IsEnabled = true;
			}
			string hpeLtfsConsoleLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Console.lnk";
			if (File.Exists(hpeLtfsConsoleLink))
			{
				btnStartLtfsConsole.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsConsoleLink);
				btnStartLtfsConsole.IsEnabled = true;
			}
			string hpeLtfsFormatWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Format Wizard.lnk";
			if (File.Exists(hpeLtfsFormatWizardLink))
			{
				btnStartLtfsFormatWizard.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsFormatWizardLink);
				btnStartLtfsFormatWizard.IsEnabled = true;
			}
			string hpeLtfsUnformatWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Unformat Wizard.lnk";
			if (File.Exists(hpeLtfsUnformatWizardLink))
			{
				btnStartLtfsUnformatWizard.Click += (object sender, System.Windows.RoutedEventArgs e) => OpenLnkFile(hpeLtfsUnformatWizardLink);
				btnStartLtfsUnformatWizard.IsEnabled = true;
			}
		}

		private static void OpenLnkFile(string filename)
		{
			Process process = new()
			{
				StartInfo = new ProcessStartInfo()
				{
					FileName = filename,
					UseShellExecute = true
				}
			};
			process.Start();
		}

		public void CurrentDriveErrorMessageChanged(object? sender, TapeDriveErrorEventArgs e)
		{
			Error = e.ErrorString;
		}

		private void BtnCreateRsaKey_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate, true, true))
			{
				Error = $"Certificate creation error";
			}
			else
			{
				X509Certificate2UI.DisplayCertificate(tpmCertificate);
			}
		}

		private void CbGlobalFingerprints_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
		{
			if (e.AddedItems is null || e.AddedItems.Count == 0 || e.AddedItems[0] is not string globalFingerprint)
			{
				return;
			}
			if (!TryEnumerateGlobalFingerprints(GlobalFingerprints, AccountFingerprints, out Exception? exception))
			{
				Error = $"Account listing error: {exception.Message}";
			}
		}

		private void CbAccountFingerprints_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
		{
			if (e.AddedItems is null || e.AddedItems.Count == 0 || cbGlobalFingerprints.SelectedIndex == -1 || e.AddedItems[0] is not string accountFingerprint)
			{
				return;
			}
			UseAccount(accountFingerprint);
		}

		private enum SecureWindowTypes
		{
			CreateNewSeedPhraseWindow = 0,
			RestoreSeedPhraseWindow = 1
		}

		private void BtnCreateAccountNewRecoverySeed_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			if (SecureBootEnabled && TpmSupported)
			{
				ShowSecureWindow(SecureWindowTypes.CreateNewSeedPhraseWindow);
			}
		}

		private void BtnCreateAccountExistingRecoverySeed_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			if (SecureBootEnabled && TpmSupported)
			{
				ShowSecureWindow(SecureWindowTypes.RestoreSeedPhraseWindow);
			}
		}

		private void ShowSecureWindow(SecureWindowTypes secureWindowType)
		{
			const NativeMethods.ACCESS_MASK dwDesiredAccess = NativeMethods.ACCESS_MASK.DESKTOP_READOBJECTS |
				NativeMethods.ACCESS_MASK.DESKTOP_CREATEWINDOW |
				NativeMethods.ACCESS_MASK.DESKTOP_CREATEMENU |
				NativeMethods.ACCESS_MASK.DESKTOP_WRITEOBJECTS |
				NativeMethods.ACCESS_MASK.DESKTOP_SWITCHDESKTOP;
			NativeMethods.SECURITY_ATTRIBUTES lpsa = new()
			{
				lpSecurityDescriptor = IntPtr.Zero,
				bInheritHandle = 1
			};
			lpsa.nLength = Marshal.SizeOf(lpsa);
			Windows.Win32.CloseDesktopSafeHandle hOldDesktop = new(Windows.Win32.PInvoke.GetThreadDesktop(Windows.Win32.PInvoke.GetCurrentThreadId()));
			if (hOldDesktop.IsInvalid)
			{
				return;
			}
			Windows.Win32.CloseDesktopSafeHandle hSecureDesktop = new(NativeMethods.CreateDesktop("Mydesktop", null, null, 0, dwDesiredAccess, ref lpsa));
			if (hSecureDesktop.IsInvalid)
			{
				return;
			}
			if (Windows.Win32.PInvoke.SwitchDesktop(hSecureDesktop) == Constants.TRUE)
			{
				Thread? thread = new(() =>
				{
					SecureDesktopThread(hSecureDesktop, secureWindowType);
				});
				thread.SetApartmentState(ApartmentState.STA);
				thread.Start();
				thread.Join();
				_ = Windows.Win32.PInvoke.SwitchDesktop(hOldDesktop);
				hSecureDesktop.Close();
				if (!TryEnumerateGlobalFingerprints(GlobalFingerprints, AccountFingerprints, out Exception? exception))
				{
					Error = $"Account listing error: {exception.Message}";
				}
			}
		}

		private static void SecureDesktopThread(SafeHandle hSecureDesktop, SecureWindowTypes secureWindowType)
		{
			if (Windows.Win32.PInvoke.SetThreadDesktop(hSecureDesktop) == Constants.TRUE)
			{
				SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
				PlayUacSound();
				switch (secureWindowType)
				{
					case SecureWindowTypes.CreateNewSeedPhraseWindow:
						SecureDesktopWindows.CreateNewSeedPhraseWindow secureCreateNewSeedPhraseWindow = new();
						secureCreateNewSeedPhraseWindow.ShowDialog();
						break;
					case SecureWindowTypes.RestoreSeedPhraseWindow:
						SecureDesktopWindows.RestoreSeedPhraseWindow secureRestoreSeedPhraseWindow = new();
						secureRestoreSeedPhraseWindow.ShowDialog();
						break;
				}
				Dispatcher.CurrentDispatcher.InvokeShutdown();
			}
		}

		private static void PlayUacSound()
		{
			string uacSoundFile = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\Media\Windows User Account Control.wav";
			if (File.Exists(uacSoundFile))
			{
				MediaPlayer player = new();
				player.Open(new(uacSoundFile));
				player.Play();
			}
		}

		private void BtnTestAccount_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			btnTestAccount.IsEnabled = false;
			if (!File.Exists(CurrentAccountDataFile))
			{
				CurrentAccountDataFile = string.Empty;
				cbAccountFingerprints.SelectedIndex = -1;
				cbGlobalFingerprints.SelectedIndex = -1;
				return;
			}
			VerifyCurrentAccount(true);
		}

		private void CbTapeDrives_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
		{
			if (e.RemovedItems is not null && e.RemovedItems.Count > 0)
			{
				for (int i = 0; i < e.RemovedItems.Count; i++)
				{
					if (e.RemovedItems[i] is TapeDrive previousTapeDrive)
					{
						previousTapeDrive.State.ErrorMessageChanged -= CurrentDriveErrorMessageChanged;
					}
				}
			}
			if (e.AddedItems is null || e.AddedItems.Count == 0 || e.AddedItems[0] is not TapeDrive tapeDrive)
			{
				btnDetectTape.IsEnabled = false;
				return;
			}
			TapeDriveSelected(tapeDrive);
		}

		private void TapeDriveSelected(TapeDrive? tapeDrive)
		{
			if (tapeDrive is not null)
			{
				tapeDrive.State.ErrorMessageChanged += CurrentDriveErrorMessageChanged;
				btnDetectTape.IsEnabled = true;
			}
		}

		private void BtnCalculateKAD_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			CalculateKAD(currentAccountSlip21Node, tbTapeLabel.Text, tbTapeKeyRollovers.Text, out kad, false);
		}

		void TapeValidationNode_FingerprintingCompleted(string? tapeValidationFingerprint)
		{
			if (kad is not null)
			{
				statusbarStatus.Content = string.Format("Key Authenticated Data generated");
				kad.TapeFingerprint = tapeValidationFingerprint;
			}
			tbDriveKAD.Text = kad?.GetKAD();
			btnTestAccount.IsEnabled = true;
		}

		private void CalculateKAD(Slip21NodeEncrypted? currentAccountSlip21Node, string tapeBarcode, string tapeKeyRolloverCount, out KeyAssociatedData? kad, bool enableEncryption = false)
		{
			kad = null;
			byte[]? tapeKey = null;
			tbDriveKAD.Text = string.Empty;
			btnCalculateKAD.IsEnabled = false;
			if (currentAccountSlip21Node is null || currentAccountSlip21Node.RSASignature is null || string.IsNullOrEmpty(tapeBarcode) || string.IsNullOrEmpty(tapeKeyRolloverCount))
			{
				btnCalculateKAD.IsEnabled = true;
				btnEnableDriveEncryption.IsEnabled = true;
				btnDisableDriveEncryption.IsEnabled = true;
				return;
			}
			if (uint.TryParse(tapeKeyRolloverCount, out uint tapeRollovercount))
			{
				kad = new(currentAccountSlip21Node, tapeBarcode, tapeRollovercount);
			}
			else
			{
				btnCalculateKAD.IsEnabled = true;
				btnEnableDriveEncryption.IsEnabled = true;
				btnDisableDriveEncryption.IsEnabled = true;
				return;
			}

			if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate, false))
			{
				tpmCertificate?.Dispose();
				btnCalculateKAD.IsEnabled = true;
				btnEnableDriveEncryption.IsEnabled = true;
				btnDisableDriveEncryption.IsEnabled = true;
				return;
			}
			using RSACng? rsaKey = (RSACng?)tpmCertificate.GetRSAPrivateKey();
			using RSACng? rsaPubKey = (RSACng?)tpmCertificate.GetRSAPublicKey();
			if (!tpmCertificate.HasPrivateKey || rsaKey == null || rsaPubKey == null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
			{
				tpmCertificate?.Dispose();
				btnCalculateKAD.IsEnabled = true;
				btnEnableDriveEncryption.IsEnabled = true;
				btnDisableDriveEncryption.IsEnabled = true;
				return;
			}
			else
			{
				bool signatureValid = rsaPubKey.VerifyData(Encoding.UTF8.GetBytes(currentAccountSlip21Node.SignablePart), Convert.FromHexString(currentAccountSlip21Node.RSASignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
				if (signatureValid)
				{
					byte[] nodeBytes = new byte[64];
					Array.Clear(nodeBytes, 0, 64);
					try
					{
						statusbarStatus.Content = "Decrypting account key to derive tape key and KAD...";
						byte[] nodeLeft = rsaKey.Decrypt(Convert.FromHexString(currentAccountSlip21Node.EncryptedLeftHex), RSAEncryptionPadding.Pkcs1);
						Array.Copy(nodeLeft, 0, nodeBytes, 0, 32);
						Slip21Node accountNode = new(nodeBytes, currentAccountSlip21Node.GlobalKeyRolloverCount.ToString(), currentAccountSlip21Node.DerivationPath);
						Slip21Node tapeNode = accountNode.GetChildNode(kad.TapeBarcode).GetChildNode(kad.TapeKeyRollovers.ToString());
						if (enableEncryption)
						{
							tapeKey = tapeNode.Right.ToArray();
						}
						Slip21ValidationNode tapeValidationNode = new(tapeNode);

						tapeValidationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
						{
							if (e)
							{
								TapeValidationNode_FingerprintingCompleted(tapeValidationNode.Fingerprint);
								btnCalculateKAD.IsEnabled = true;
								if (string.IsNullOrWhiteSpace(tbDriveKAD.Text) || !tbDriveKAD.Text.StartsWith(tbTapeLabel.Text[..6]))
								{
									if (string.IsNullOrWhiteSpace(tbDriveKAD.Text) || !tbDriveKAD.Text.StartsWith(tbTapeLabel.Text[..6]))
									{
										Error = "Error: KAD/Barcode mismatch.";
										return;
									}
								}

								if (enableEncryption)
								{
									Dispatcher.Invoke(() => Error = "Enabling encryption...");
									string kadString = tbDriveKAD.Text;
									new Thread(() =>
									{
										TapeDrive currentDrive = TapeDrives[0];
										currentDrive.Handle = Windows.Win32.PInvoke.CreateFile(currentDrive.Path, (uint)(GENERIC_ACCESS_RIGHTS.GENERIC_WRITE | GENERIC_ACCESS_RIGHTS.GENERIC_READ), FILE_SHARE_MODE.FILE_SHARE_READ, null, FILE_CREATION_DISPOSITION.OPEN_EXISTING, 0, null);
										if (TryWrapKey(currentDrive, ref tapeKey, out byte[]? wrappedKey))
										{
											if (tapeKey is not null)
											{
												Array.Clear(tapeKey, 0, tapeKey.Length);
											}
											//Trace.WriteLine($"Wrapped Key: {Convert.ToHexString(wrappedKey)}");
											SPTI.LTO.EnableTapeDriveEncryption(currentDrive, ref wrappedKey, kadString);
											Dispatcher.Invoke(() =>
											{
												Error = currentDrive.State.DisplayLastErrorMessage;
												btnEnableDriveEncryption.IsEnabled = true;
												btnDisableDriveEncryption.IsEnabled = true;
											});
										}
										currentDrive.Handle.Close();
									}).Start();
								}
							}
						});
						statusbarStatus.Content = "Calculating Key Authenticated Data...";
						tapeValidationNode.CalculateFingerprint(24);
					}
					catch (Exception ex)
					{
						Error = $"Decryption Error: {ex.Message}";
						btnTestAccount.IsEnabled = true;
						btnCalculateKAD.IsEnabled = true;
						btnEnableDriveEncryption.IsEnabled = true;
						btnDisableDriveEncryption.IsEnabled = true;
					}
				}
				tpmCertificate?.Dispose();
				return;
			}
		}

		private void BtnEnableDriveEncryption_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			if (string.IsNullOrWhiteSpace(tbTapeLabel.Text) || tbTapeLabel.Text.Length != 8)
			{
				Error = "Error: 8 character tape barcode required, such as LTO123L6.";
				return;
			}
			else if (string.IsNullOrWhiteSpace(tbTapeKeyRollovers.Text))
			{
				Error = "Error: Tape key rollover count required.";
				return;
			}
			else if (cbTapeDrives.SelectedIndex == -1 || TapeDrives.Count <= cbTapeDrives.SelectedIndex || TapeDrives[cbTapeDrives.SelectedIndex] is null)
			{
				Error = "Error: No tape drive selected.";
				return;
			}

			btnEnableDriveEncryption.IsEnabled = false;
			btnDisableDriveEncryption.IsEnabled = false;
			CalculateKAD(currentAccountSlip21Node, tbTapeLabel.Text, tbTapeKeyRollovers.Text, out kad, true);
		}

		public static bool TryWrapKey(TapeDrive tapeDrive, ref byte[]? key, [NotNullWhen(true)] out byte[]? wrappedKey)
		{
			wrappedKey = null;
			if (tapeDrive is null || tapeDrive.KeyWrapPublicKey is null || tapeDrive.WrappedKeyDescriptors is null || key is null)
			{
				return false;
			}
			byte[] pubkey = tapeDrive.KeyWrapPublicKey; // RSAES-OAEP-ENCRYPT parameter (n, e)
														// key: RSAES-OAEP-ENCRYPT parameter M
			byte[] label = tapeDrive.WrappedKeyDescriptors; // RSAES-OAEP-ENCRYPT parameter L
			Org.BouncyCastle.Crypto.Encodings.OaepEncoding oaepEncoding = new(new Org.BouncyCastle.Crypto.Engines.RsaEngine(), new Org.BouncyCastle.Crypto.Digests.Sha256Digest(), new Org.BouncyCastle.Crypto.Digests.Sha256Digest(), label);
			using RSA RSA = RSA.Create();
			RSA.ImportRSAPublicKey(pubkey, out int keyLength);
			RSAParameters pubKeyParamsRSA = RSA.ExportParameters(false);
			if (pubKeyParamsRSA.Modulus is null || pubKeyParamsRSA.Exponent is null)
			{
				return false;
			}
			byte[] modulus;
			if (pubKeyParamsRSA.Modulus[0] == 0x00)
			{
				modulus = pubKeyParamsRSA.Modulus;
			}
			else
			{
				modulus = new byte[pubKeyParamsRSA.Modulus.Length + 1];
				Array.Copy(pubKeyParamsRSA.Modulus, 0, modulus, 1, pubKeyParamsRSA.Modulus.Length);
			}
			Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters pubKeyParams = new(false, new(modulus, 0, modulus.Length), new(pubKeyParamsRSA.Exponent, 0, pubKeyParamsRSA.Exponent.Length));
			oaepEncoding.Init(true, pubKeyParams);
			wrappedKey = oaepEncoding.ProcessBlock(key, 0, key.Length);
			return true;
		}

		private void BtnDisableDriveEncryption_Click(object sender, System.Windows.RoutedEventArgs e)
		{
			TapeDrive currentDrive = TapeDrives[0];
			currentDrive.Handle = Windows.Win32.PInvoke.CreateFile(currentDrive.Path, (uint)(GENERIC_ACCESS_RIGHTS.GENERIC_WRITE | GENERIC_ACCESS_RIGHTS.GENERIC_READ), FILE_SHARE_MODE.FILE_SHARE_READ, null, FILE_CREATION_DISPOSITION.OPEN_EXISTING, 0, null);
			SPTI.LTO.DisableTapeDriveEncryption(currentDrive);
			Error = currentDrive.State.DisplayLastErrorMessage;
			currentDrive.Handle.Close();
		}
	}
}
