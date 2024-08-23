using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using Tpm2Lib;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SecureDesktopWindows
{
	public partial class CreateNewSeedPhraseWindow : Form
	{
		//Process[] processCollection;
		private byte[]? binarySeed;
		bool validTpmCert;

		public CreateNewSeedPhraseWindow()
		{
			InitializeComponent();
			//processCollection = Process.GetProcesses();
			//statusLabel.Text = $"Number of processes: {processCollection.Length}";
			validTpmCert = ValidCertificateExists();
			statusLabel.Text = validTpmCert ? "OK: TPM-backed certificate exists" : "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
			btnGenerateSeed.Enabled = validTpmCert;
			tbGlobalRollovers.ReadOnly = !validTpmCert;
			tbAccount.ReadOnly = !validTpmCert;
			tbAccountRollovers.ReadOnly = !validTpmCert;
		}

		private void ProgressBarParseEntropy()
		{
			progressBar.Style = ProgressBarStyle.Continuous;
			progressBar.Step = 1;
			progressBar.Minimum = 0;
			progressBar.Value = 0;
			progressBar.Maximum = 24;
			Refresh();
		}

		private void ProgressBarStart()
		{
			progressBar.Style = ProgressBarStyle.Marquee;
			progressBar.MarqueeAnimationSpeed = 60;
		}

		private void ProgressBarComplete()
		{
			progressBar.Style = ProgressBarStyle.Continuous;
			progressBar.Minimum = 0;
			progressBar.Maximum = 100;
			progressBar.Value = progressBar.Maximum;
			Refresh();
		}

		private void ProgressBarStop()
		{
			progressBar.Style = ProgressBarStyle.Continuous;
			progressBar.Minimum = 0;
			progressBar.Maximum = 100;
			progressBar.Value = 0;
		}

		private static bool ValidCertificateExists()
		{
			using X509Certificate2? tpmCertificate = Utils.PKI.GetOrCreateRsaCertificate(true);
			if (tpmCertificate is null)
			{
				return false;
			}
			using RSA? rsaPrivateKey = tpmCertificate.GetRSAPrivateKey();
			using RSACng? rsaCngKey = rsaPrivateKey is RSACng ? rsaPrivateKey as RSACng : null;
			using RSA? rsaPublicKey = tpmCertificate.GetRSAPublicKey();
			bool useableCert = tpmCertificate.HasPrivateKey == true && rsaPrivateKey is not null && rsaPublicKey is not null && rsaCngKey is not null && rsaCngKey.Key.ExportPolicy == CngExportPolicies.None;
			return useableCert;
		}

		private void ResetSeedPhraseDisplay()
		{
			binarySeed = null;
			lblSeedHex1.Text = string.Empty;
			lblSeedHex2.Text = string.Empty;
			lblSeedHex3.Text = string.Empty;
			lblSeedHex4.Text = string.Empty;
			ResetFingerprintDisplay();
		}

		private void ResetFingerprintDisplay()
		{
			tbSeedFingerprint.Text = string.Empty;
			tbAccountFingerprint.Text = string.Empty;
		}

		private void BtnGenerateSeed_Click(object sender, EventArgs e)
		{
			ProgressBarParseEntropy();
			ResetSeedPhraseDisplay();

			using Tpm2Device tpmDevice = new TbsDevice();

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

			using X509Certificate2? tpmCertificate = Utils.PKI.GetOrCreateRsaCertificate(true);
			if (tpmCertificate is null)
			{
				statusLabel.Text = $"Certificate/Key error";
				binarySeed = null;
				ProgressBarStop();
				return;
			}

			if (validTpmCert)
			{
				try
				{
					RSA? rsaPrivateKey = tpmCertificate.GetRSAPrivateKey();
					RSACng? rsaCngKey = rsaPrivateKey is RSACng ? rsaPrivateKey as RSACng : null;
					RSA? rsaPublicKey = tpmCertificate.GetRSAPublicKey();
					validTpmCert = tpmCertificate.HasPrivateKey == true && rsaPrivateKey is not null && rsaPublicKey is not null && rsaCngKey is not null && rsaCngKey.Key.ExportPolicy == CngExportPolicies.None;
				}
				catch (Exception)
				{
					validTpmCert = false;
				}
			}
			if (!validTpmCert)
			{
				statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
				btnGenerateSeed.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				ProgressBarStop();
				return;
			}

			try
			{
				progressBar.Maximum = 25;
				progressBar.Step = 1;
				byte[] entropyBytes = tpm.GetRandom(32);
				progressBar.PerformStep();
				//Array.Clear(SeedBytes, 0, SeedBytes.Length);
				//byte[] entropyBytes = Convert.FromHexString("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f");
				string seedMnemonic = Bip39.GetMnemonicFromEntropy(BitConverter.ToString(entropyBytes).Replace("-", "", StringComparison.InvariantCulture).ToUpperInvariant());
				Array.Clear(entropyBytes, 0, entropyBytes.Length);
				string[] seedMnemonicSplit = seedMnemonic.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
				progressBar.Step = 6;
				binarySeed = Bip39.GetBinarySeedFromSeedWords(ref seedMnemonicSplit, null);
				lblSeedHex1.Text = seedMnemonicSplit.Length >= 6 ? string.Format(CultureInfo.InvariantCulture, "{0} {1} {2} {3} {4} {5}", seedMnemonicSplit) : string.Empty;
				progressBar.PerformStep();
				lblSeedHex2.Text = seedMnemonicSplit.Length >= 12 ? string.Format(CultureInfo.InvariantCulture, "{6} {7} {8} {9} {10} {11}", seedMnemonicSplit) : string.Empty;
				progressBar.PerformStep();
				lblSeedHex3.Text = seedMnemonicSplit.Length >= 18 ? string.Format(CultureInfo.InvariantCulture, "{12} {13} {14} {15} {16} {17}", seedMnemonicSplit) : string.Empty;
				progressBar.PerformStep();
				lblSeedHex4.Text = seedMnemonicSplit.Length >= 24 ? string.Format(CultureInfo.InvariantCulture, "{18} {19} {20} {21} {22} {23}", seedMnemonicSplit) : string.Empty;
				progressBar.PerformStep();
				statusLabel.Text = "Success. Write down the new BIP39 recovery seed and store it securely, then derive the account node.";
				btnDeriveAccountNode.Enabled = validTpmCert;
			}
			catch (Exception ex)
			{
				statusLabel.Text = $"Exception occurred: {ex.Message}";
				ResetSeedPhraseDisplay();
			}
			finally
			{
				ProgressBarComplete();
			}
		}

		private void BtnDeriveAccountNode_Click(object sender, EventArgs e)
		{
			ProgressBarStart();
			ResetFingerprintDisplay();

			if (binarySeed == null)
			{
				ProgressBarStop();
				return;
			}

			using X509Certificate2? tpmCertificate = Utils.PKI.GetOrCreateRsaCertificate(true);
			if (tpmCertificate is null)
			{
				statusLabel.Text = "Certificate/Key error";
				binarySeed = null;
				ProgressBarStop();
				return;
			}

			RSA? rsaPrivateKey = null;
			RSACng? rsaCngKey = null;
			RSA? rsaPublicKey = null;
			if (validTpmCert)
			{
				try
				{
					rsaPrivateKey = tpmCertificate.GetRSAPrivateKey();
					rsaCngKey = rsaPrivateKey is RSACng ? rsaPrivateKey as RSACng : null;
					rsaPublicKey = tpmCertificate.GetRSAPublicKey();
					validTpmCert = tpmCertificate.HasPrivateKey == true && rsaPrivateKey is not null && rsaPublicKey is not null && rsaCngKey is not null && rsaCngKey.Key.ExportPolicy == CngExportPolicies.None;
				}
				catch (Exception)
				{
					validTpmCert = false;
				}
			}

			void Cleanup()
			{
				rsaPrivateKey?.Dispose();
				rsaCngKey?.Dispose();
				rsaPublicKey?.Dispose();
				tpmCertificate?.Dispose();
				ProgressBarStop();
			}

			if (!validTpmCert)
			{
				statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
				btnGenerateSeed.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}
			if (rsaPublicKey is null)
			{
				statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) does not have a public key";
				btnGenerateSeed.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}

			string firstLevelLabel = Utils.Properties.Resources.slip21_schema_lto_aes256gcm;
			Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(binarySeed, tbGlobalRollovers.Text);
			Slip21Node globalNode = masterNode.GetChildNode(firstLevelLabel).GetChildNode(tbGlobalRollovers.Text);
			Slip21ValidationNode validationNode = new(globalNode);
			Slip21Node accountNode = masterNode.GetChildNode(firstLevelLabel).GetChildNode(tbGlobalRollovers.Text).GetChildNode(tbAccount.Text).GetChildNode(tbAccountRollovers.Text);
			Slip21NodeEncrypted? slip21NodeEncrypted = null;

			byte[]? encryptedLeft = null;
			try
			{
				encryptedLeft = rsaPublicKey.Encrypt(accountNode.Left.ToArray(), RSAEncryptionPadding.Pkcs1);
			}
			// RSACng.Encrypt (ArgumentNullException): arguments data and/or padding are null
			// RSACng.Encrypt (CryptographicException): argument padding has Mode property that is not Pkcs1 or Oaep
			catch (Exception)
			{
				btnGenerateSeed.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}
			string? encryptedLeftHex = null;
			try
			{
				encryptedLeftHex = Convert.ToHexString(encryptedLeft);
			}
			// Convert.ToHexString (ArgumentNullException): argument inArray is null
			// Convert.ToHexString (ArgumentOutOfRangeException): argument inArray is too large to be encoded
			catch (Exception)
			{
				btnGenerateSeed.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}
			slip21NodeEncrypted = new(encryptedLeftHex, accountNode.DerivationPath, accountNode.GlobalKeyRolloverCount);
			statusLabel.Text = slip21NodeEncrypted.SignablePart[512..].Replace('\x001F', '|');

			Slip21ValidationNode accountValidationNode = new(accountNode);
			validationNode.FingerprintingStarted += new EventHandler<FingerprintingStartedEventArgs>((sender, e) =>
			{
				if (e.HasStarted)
				{
					ProgressBarStart();
					tbSeedFingerprint.Text = "Calculating...";
				}
			});
			validationNode.FingerprintingCompleted += new EventHandler<FingerprintingCompletedEventArgs>((sender, e) =>
			{
				if (e.HasCompleted)
				{
					ProgressBarStop();
					tbSeedFingerprint.Text = validationNode.Fingerprint ?? string.Empty;
					accountValidationNode.CalculateFingerprint();
					if (slip21NodeEncrypted != null)
					{
						slip21NodeEncrypted.GlobalFingerprint = validationNode.Fingerprint;
					}
				}
			});
			accountValidationNode.FingerprintingStarted += new EventHandler<FingerprintingStartedEventArgs>((sender, e) =>
			{
				if (e.HasStarted)
				{
					ProgressBarStart();
					tbAccountFingerprint.Text = "Calculating...";
				}
			});
			accountValidationNode.FingerprintingCompleted += new EventHandler<FingerprintingCompletedEventArgs>((sender, e) =>
			{
				if (e.HasCompleted)
				{
					tbAccountFingerprint.Text = accountValidationNode.Fingerprint ?? string.Empty;
					if (rsaCngKey is null || slip21NodeEncrypted is null || slip21NodeEncrypted.GlobalFingerprint is null || accountValidationNode.Fingerprint is null)
					{
						Cleanup();
						return;
					}
					slip21NodeEncrypted.AccountFingerprint = accountValidationNode.Fingerprint;

					string? thisAppDataFolder = null;
					try
					{
						string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
						string globalFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.GlobalFingerprint));
						thisAppDataFolder = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts", globalFingerprintHex);
						if (!Directory.Exists(thisAppDataFolder))
						{
							Directory.CreateDirectory(thisAppDataFolder);
						}
						ProgressBarComplete();
					}
					catch (Exception pathCheckException)
					{
						statusLabel.Text = $"Account data storage error: {pathCheckException.Message}";
					}
					if (thisAppDataFolder is null)
					{
						Cleanup();
						return;
					}

					statusLabel.Text = "Signing SLIP21 node data...";
					byte[]? nodeDataSigned = null;
					try
					{
						nodeDataSigned = rsaCngKey.SignData(Encoding.UTF8.GetBytes(slip21NodeEncrypted.SignablePart), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
						slip21NodeEncrypted.RSASignature = Convert.ToHexString(nodeDataSigned);
						statusLabel.Text = $"Signature length: {slip21NodeEncrypted.RSASignature.Length} bytes";
					}
					catch (Exception accountDataSigningException)
					{
						statusLabel.Text = $"Account data signing error: {accountDataSigningException.Message}";
					}
					if (nodeDataSigned is null)
					{
						Cleanup();
						return;
					}

					try
					{
						ProgressBarStart();
						string accountFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.AccountFingerprint));
						using StreamWriter file = new(Path.Combine(thisAppDataFolder, $"{accountFingerprintHex}.blob"), false, Encoding.UTF8, 4096);
						StringBuilder nodeBackupData = new();
						nodeBackupData.Append(slip21NodeEncrypted.SignablePart).Append('\x001E').Append(slip21NodeEncrypted.RSASignature);
						file.WriteAsync(nodeBackupData.ToString());
						file.Close();
						ProgressBarComplete();
						DialogResult = DialogResult.OK;
						Dispose();
					}
					catch (Exception accountDataStorageException)
					{
						statusLabel.Text = $"Account data storage error: {accountDataStorageException.Message}";
						Cleanup();
						return;
					}
				}
			});
			validationNode.CalculateFingerprint();
		}
	}
}
