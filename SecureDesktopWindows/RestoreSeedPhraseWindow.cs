using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SecureDesktopWindows
{
	public partial class RestoreSeedPhraseWindow : Form, INotifyPropertyChanged
	{
		public event PropertyChangedEventHandler? PropertyChanged;
		private byte[]? binarySeed;
		bool validTpmCert;
		bool comboboxesPopulated;
		public Collection<string> Bip39Dictionary { get; private set; }
		private Bip39SeedPhrase _newSeedPhrase = new();
		public Bip39SeedPhrase NewSeedPhrase => _newSeedPhrase;
		private SecureString? Passphrase { get; set; }
		private Slip21Schema _firstLevelLabel;
		public Slip21Schema FirstLevelLabel
		{
			get => _firstLevelLabel;
			set
			{
				_firstLevelLabel = value;
				OnPropertyChanged();
			}
		}
		public Collection<Slip21Schema> FirstLevelLabels { get; private set; }
		public string GlobalKeyRollovers { get; set; }
		public string SeedDerivationPath { get; set; } = string.Empty;
		public string SeedValidationFingerprint { get; set; } = string.Empty;
		private Color _validationStatusColor = SystemColors.WindowText;
		public Color ValidationStatusColor
		{
			get => _validationStatusColor;
			set
			{
				_validationStatusColor = value;
				OnPropertyChanged();
			}
		}
		private string _validationStatusMessage = string.Empty;
		public string ValidationStatusMessage
		{
			get => _validationStatusMessage;
			set
			{
				_validationStatusMessage = value;
				OnPropertyChanged();
			}
		}
		public string AccountID { get; set; } = string.Empty;
		public string AccountKeyRollovers { get; set; } = string.Empty;
		public string AccountDerivationPath { get; set; } = string.Empty;
		public string AccountValidationFingerprint { get; set; } = string.Empty;
		Collection<ComboBox>? cbWordList;

		public RestoreSeedPhraseWindow()
		{
			InitializeComponent();
			Shown += Form_Shown;
			Bip39Dictionary = [];
			FirstLevelLabels =
			[
				new Slip21Schema(Utils.Properties.Resources.slip21_schema_lto_aes256gcm),
				new Slip21Schema(Utils.Properties.Resources.slip21_schema_snowflake_hmacSha256)
			];
			_firstLevelLabel = FirstLevelLabels[0];
			OnPropertyChanged(nameof(FirstLevelLabel));
			GlobalKeyRollovers = "0";
		}

		private void Form_Shown(object? sender, EventArgs e)
		{
			statusLabel.Text = Properties.Resources.status_loading_content;
			btnValidateSeedPhrase.Enabled = false;
			btnDeriveAccountNode.Enabled = false;
			Refresh();
			GenerateBip39Dictionary();
			comboboxesPopulated = true;
			NewSeedPhrase.Length = 24;

			AccountID = "0";
			AccountKeyRollovers = "0";
			NewSeedPhrase.PropertyChanged += new((sender, e) =>
			{
				if (e.PropertyName != nameof(Bip39BinarySeed.ValidationStatusMessage))
				{
					ValidationStatusMessage = string.Empty;
				}
			});
			lblValidationStatus.DataBindings.Add("ForeColor", this, nameof(ValidationStatusColor));
			lblValidationStatus.DataBindings.Add("Text", this, nameof(ValidationStatusMessage));
			tbGlobalRollovers.DataBindings.Add("Text", this, nameof(GlobalKeyRollovers));
			tbAccount.DataBindings.Add("Text", this, nameof(AccountID));
			tbAccountRollovers.DataBindings.Add("Text", this, nameof(AccountKeyRollovers));
			tbSeedFingerprint.DataBindings.Add("Text", this, nameof(SeedValidationFingerprint));
			tbAccountFingerprint.DataBindings.Add("Text", this, nameof(AccountValidationFingerprint));
			validTpmCert = ValidCertificateExists();
			statusLabel.Text = validTpmCert ? Properties.Resources.tpm_cert_found : Properties.Resources.tpm_cert_not_found;
			btnValidateSeedPhrase.Enabled = !NewSeedPhrase.HasErrors;
			tbGlobalRollovers.ReadOnly = !validTpmCert;
			tbAccount.ReadOnly = !validTpmCert;
			tbAccountRollovers.ReadOnly = !validTpmCert;
			ProgressBarComplete();
			Refresh();
		}

		private void ProgressBarStartLoadDictionary()
		{
			progressBar.Style = ProgressBarStyle.Continuous;
			progressBar.Value = 0;
			progressBar.Step = 1;
			progressBar.Minimum = 1;
			progressBar.Maximum = 24;
			Refresh();
		}

		private void ProgressBarComplete()
		{
			progressBar.Style = ProgressBarStyle.Continuous;
			progressBar.Value = progressBar.Maximum;
			Refresh();
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

		private void InitComboBoxSeedWord(ComboBox cbWord)
		{
			//string propertyName = $"Word{i + 1:00}";
			//cbWord.BindingContext = wordNumber;
			cbWord.DataSource = new BindingList<string>(Bip39Dictionary);
			cbWord.Validating += CbWord_Validating;
		}

		private async void GenerateBip39Dictionary()
		{
			ProgressBarStartLoadDictionary();
			await Bip39.GetWordValues(Bip39Dictionary).ConfigureAwait(false);
			cbWordList =
			[
				cbWord1, cbWord2, cbWord3, cbWord4, cbWord5, cbWord6, cbWord7, cbWord8, cbWord9, cbWord10, cbWord11, cbWord12, cbWord13, cbWord14, cbWord15, cbWord16, cbWord17, cbWord18, cbWord19, cbWord20, cbWord21, cbWord22, cbWord23, cbWord24
			];
			for (int i = 0; i < 24; ++i)
			{
				cbWordList[i].BeginUpdate();
				InitComboBoxSeedWord(cbWordList[i]);
				cbWordList[i].SelectedIndex = -1;
				cbWordList[i].EndUpdate();
				progressBar.PerformStep();
				Refresh();
			}
		}

		private void RestoreSeedPhraseWindow_SelectedIndexChanged(object? sender, EventArgs e)
		{
			if (sender is not ComboBox cbWord || !comboboxesPopulated)
			{
				return;
			}
			int? cbWordIndex = cbWordList?.IndexOf(cbWord);
			string propertyName = $"Word{cbWordIndex + 1:00}";
			typeof(Bip39SeedPhrase).GetProperty(propertyName)?.SetValue(NewSeedPhrase, cbWord.SelectedIndex);
			btnValidateSeedPhrase.Enabled = !NewSeedPhrase.HasErrors;
		}

		private void CbWord_Validating(object? sender, CancelEventArgs e)
		{
			if (sender is not ComboBox cbWord || !comboboxesPopulated)
			{
				return;
			}
			btnDeriveAccountNode.Enabled = false;
			if (cbWord.SelectedIndex == -1)
			{
				int? cbWordIndex = cbWordList?.IndexOf(cbWord);
				string propertyName = $"Word{cbWordIndex + 1:00}";
				typeof(Bip39SeedPhrase).GetProperty(propertyName)?.SetValue(NewSeedPhrase, cbWord.SelectedIndex);
				btnValidateSeedPhrase.Enabled = !NewSeedPhrase.HasErrors;
				cbWord.ForeColor = Color.Red;
			}
			else
			{
				cbWord.ForeColor = SystemColors.WindowText;
				ValidationStatusMessage = string.Empty;
			}
		}

		protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		private void ValidateSeedPhrase(object sender, EventArgs e)
		{
			if (cbWordList is null || !comboboxesPopulated)
			{
				return;
			}
			if (NewSeedPhrase.HasErrors)
			{
				Dictionary<string, List<string>> errors = (Dictionary<string, List<string>>)NewSeedPhrase.GetErrors(null);
				ValidationStatusMessage = errors.First().Value[0];
				return;
			}
			foreach (ComboBox cbWord in cbWordList)
			{
				if (cbWord.SelectedIndex == -1)
				{
					ValidationStatusColor = Color.Red;
					ValidationStatusMessage = Properties.Resources.error_bip39_missing_word;
					return;
				}
			}
			ValidationStatusMessage = Properties.Resources.bip39_validated;
			ValidationStatusColor = SystemColors.WindowText;
			Bip39BinarySeed bip39BinarySeed = new(ref _newSeedPhrase);
			if (bip39BinarySeed.TryGetBinarySeed(_newSeedPhrase.HasEmptyPassphrase ? null : Passphrase, out binarySeed))
			{
				ValidationStatusColor = Color.Green;
				ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
				btnDeriveAccountNode.Enabled = true;
			}
			else
			{
				ValidationStatusColor = Color.Red;
				ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
				btnDeriveAccountNode.Enabled = false;
				SeedDerivationPath = string.Empty;
				OnPropertyChanged(nameof(SeedDerivationPath));
				SeedValidationFingerprint = string.Empty;
				OnPropertyChanged(nameof(SeedValidationFingerprint));
				AccountDerivationPath = string.Empty;
				OnPropertyChanged(nameof(AccountDerivationPath));
				AccountValidationFingerprint = string.Empty;
				OnPropertyChanged(nameof(AccountValidationFingerprint));
			}
		}

		private void LockSeedPhrase(bool isReadOnly)
		{
			if (cbWordList is null)
			{
				return;
			}
			foreach (ComboBox cbWord in cbWordList)
			{
				cbWord.Enabled = isReadOnly;
			}
		}

		private void ResetFingerprintDisplay()
		{
			tbSeedFingerprint.Text = string.Empty;
			tbAccountFingerprint.Text = string.Empty;
		}

		private void BtnDeriveAccountNode_Click(object sender, EventArgs e)
		{
			ResetFingerprintDisplay();

			if (binarySeed == null)
			{
				return;
			}

			using X509Certificate2? tpmCertificate = Utils.PKI.GetOrCreateRsaCertificate(true);
			if (tpmCertificate is null)
			{
				statusLabel.Text = Properties.Resources.cert_key_error;
				binarySeed = null;
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
				// RSA.GetRSAPrivateKey (ArgumentNullException)
				// RSA.GetRSAPublicKey (ArgumentNullException)
				// RSA.GetRSAPublicKey (CryptographicException)
				catch (Exception ex) when
				(ex is ArgumentNullException || ex is CryptographicException)
				{
					validTpmCert = false;
				}
			}

			void Cleanup()
			{
				rsaPrivateKey?.Dispose();
				rsaCngKey?.Dispose();
				rsaPublicKey?.Dispose();
			}

			if (!validTpmCert)
			{
				statusLabel.Text = Properties.Resources.tpm_cert_not_found;
				LockSeedPhrase(true);
				btnValidateSeedPhrase.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}
			if (rsaPublicKey is null)
			{
				statusLabel.Text = Properties.Resources.tpm_cert_no_pubkey;
				LockSeedPhrase(true);
				btnValidateSeedPhrase.Enabled = false;
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
				encryptedLeft = rsaPublicKey.Encrypt([.. accountNode.Left], RSAEncryptionPadding.Pkcs1);
			}
			// RSA.Encrypt (ArgumentNullException)
			// RSA.Encrypt (NotImplementedException)
			// RSA.Encrypt (CryptographicException)
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is NotImplementedException || ex is CryptographicException)
			{
				LockSeedPhrase(true);
				btnValidateSeedPhrase.Enabled = false;
				btnDeriveAccountNode.Enabled = false;
				Cleanup();
				return;
			}
			string? encryptedLeftHex = null;
			try
			{
				encryptedLeftHex = Convert.ToHexString(encryptedLeft);
			}
			// Convert.ToHexString (ArgumentNullException)
			// Convert.ToHexString (ArgumentOutOfRangeException)
			catch (Exception ex) when
			(ex is ArgumentNullException || ex is ArgumentOutOfRangeException)
			{
				LockSeedPhrase(true);
				btnValidateSeedPhrase.Enabled = false;
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
					tbSeedFingerprint.Text = Properties.Resources.status_calculating;
				}
			});
			validationNode.FingerprintingCompleted += new EventHandler<FingerprintingCompletedEventArgs>((sender, e) =>
			{
				if (e.HasCompleted)
				{
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
					tbAccountFingerprint.Text = Properties.Resources.status_calculating;
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
					}
					// Environment.GetFolderPath (ArgumentException)
					// Environment.GetFolderPath (PlatformNotSupportedException)
					// Convert.ToHexString (ArgumentNullException)
					// Convert.ToHexString (ArgumentOutOfRangeException)
					// Encoding.GetBytes (ArgumentNullException)
					// Encoding.GetBytes (EncoderFallbackException)
					// Path.Combine (ArgumentException)
					// Path.Combine (ArgumentNullException)
					// Directory.CreateDirectory (IOException)
					// Directory.CreateDirectory (UnauthorizedAccessException)
					// Directory.CreateDirectory (ArgumentException)
					// Directory.CreateDirectory (ArgumentNullException)
					// Directory.CreateDirectory (PathTooLongException)
					// Directory.CreateDirectory (DirectoryNotFoundException)
					// Directory.CreateDirectory (NotSupportedException)
					catch (Exception ex) when
					(ex is ArgumentException || ex is PlatformNotSupportedException || ex is ArgumentNullException || ex is ArgumentOutOfRangeException
					|| ex is EncoderFallbackException || ex is IOException || ex is UnauthorizedAccessException || ex is PathTooLongException
					|| ex is DirectoryNotFoundException || ex is NotSupportedException)
					{
						statusLabel.Text = $"Account data storage error: {ex.Message}";
					}
					if (thisAppDataFolder is null)
					{
						Cleanup();
						return;
					}

					statusLabel.Text = Properties.Resources.status_signing_node;
					byte[]? nodeDataSigned = null;
					try
					{
						nodeDataSigned = rsaCngKey.SignData(Encoding.UTF8.GetBytes(slip21NodeEncrypted.SignablePart), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
						slip21NodeEncrypted.RSASignature = Convert.ToHexString(nodeDataSigned);
						statusLabel.Text = $"Signature length: {slip21NodeEncrypted.RSASignature.Length} bytes";
					}
					// RSA.SignData (ArgumentNullException)
					// RSA.SignData (ArgumentException)
					// RSA.SignData (CryptographicException)
					// Encoding.GetBytes (ArgumentNullException)
					// Encoding.GetBytes (EncoderFallbackException)
					// Convert.ToHexString (ArgumentNullException)
					// Convert.ToHexString (ArgumentOutOfRangeException)
					catch (Exception ex) when
					(ex is ArgumentNullException || ex is ArgumentException || ex is CryptographicException || ex is EncoderFallbackException
					|| ex is ArgumentOutOfRangeException)
					{
						statusLabel.Text = $"Account data signing error: {ex.Message}";
					}
					if (nodeDataSigned is null)
					{
						Cleanup();
						return;
					}

					try
					{
						string accountFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.AccountFingerprint));
						using StreamWriter file = new(Path.Combine(thisAppDataFolder, $"{accountFingerprintHex}.blob"), false, Encoding.UTF8, 4096);
						StringBuilder nodeBackupData = new();
						nodeBackupData.Append(slip21NodeEncrypted.SignablePart).Append('\x001E').Append(slip21NodeEncrypted.RSASignature);
						file.WriteAsync(nodeBackupData.ToString());
						file.Close();
						DialogResult = DialogResult.OK;
						Dispose();
					}
					// Convert.ToHexString (ArgumentNullException)
					// Convert.ToHexString (ArgumentOutOfRangeException)
					// Encoding.GetBytes (ArgumentNullException)
					// Encoding.GetBytes (EncoderFallbackException)
					// StreamWriter.StreamWriter (ArgumentException)
					// StreamWriter.StreamWriter (ArgumentNullException)
					// StreamWriter.StreamWriter (ArgumentOutOfRangeException)
					// StreamWriter.StreamWriter (IOException)
					// StreamWriter.StreamWriter (SecurityException)
					// StreamWriter.StreamWriter (UnauthorizedAccessException)
					// StreamWriter.StreamWriter (DirectoryNotFoundException)
					// StreamWriter.StreamWriter (PathTooLongException)
					// Path.Combine (ArgumentException)
					// Path.Combine (ArgumentNullException)
					// StringBuilder.Append (ArgumentOutOfRangeException)
					// StreamWriter.WriteAsync (ObjectDisposedException)
					// StreamWriter.WriteAsync (InvalidOperationException)
					// StreamWriter.Close (EncoderFallbackException)
					catch (Exception ex) when
					(ex is ArgumentNullException || ex is ArgumentOutOfRangeException || ex is EncoderFallbackException || ex is ArgumentOutOfRangeException
					|| ex is ArgumentException || ex is IOException || ex is SecurityException || ex is UnauthorizedAccessException
					|| ex is DirectoryNotFoundException || ex is PathTooLongException || ex is ObjectDisposedException || ex is InvalidOperationException)
					{
						statusLabel.Text = $"Account data storage error: {ex.Message}";
						Cleanup();
						return;
					}
				}
			});
			validationNode.CalculateFingerprint();
		}
	}
}
