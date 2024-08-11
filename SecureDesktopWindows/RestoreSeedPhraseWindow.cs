using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Input;
using uk.JohnCook.dotnet.LTOEncryptionManager.Commands;
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
        public List<string> Bip39Dictionary { get; private set; }
        private Bip39SeedPhrase _newSeedPhrase = new();
        public Bip39SeedPhrase NewSeedPhrase => _newSeedPhrase;
        public SecureString? Passphrase { private get; set; }
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
        public List<Slip21Schema> FirstLevelLabels { get; private set; }
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
        List<ComboBox>? cbWordList = null;

        public RestoreSeedPhraseWindow()
        {
            InitializeComponent();
            Shown += Form_Shown;
            Bip39Dictionary = new();
            FirstLevelLabels = new()
            {
                new Slip21Schema(Utils.Properties.Resources.slip21_schema_lto_aes256gcm),
                new Slip21Schema(Utils.Properties.Resources.slip21_schema_snowflake_hmacSha256)
            };
            _firstLevelLabel = FirstLevelLabels[0];
            OnPropertyChanged(nameof(FirstLevelLabel));
            GlobalKeyRollovers = "0";
        }

        private void Form_Shown(object? sender, EventArgs e)
        {
            statusLabel.Text = "Loading window content...";
            Refresh();
            GenerateBip39Dictionary();
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
            statusLabel.Text = validTpmCert ? "OK: TPM-backed certificate exists" : "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
            btnValidateSeedPhrase.Enabled = !NewSeedPhrase.HasErrors;
            tbGlobalRollovers.ReadOnly = !validTpmCert;
            tbAccount.ReadOnly = !validTpmCert;
            tbAccountRollovers.ReadOnly = !validTpmCert;
            Refresh();
        }

        private static bool ValidCertificateExists()
        {
            if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate, true))
            {
                return false;
            }
            using RSA? rsaPrivateKey = tpmCertificate?.GetRSAPrivateKey();
            using RSACng? rsaCngKey = rsaPrivateKey is RSACng ? rsaPrivateKey as RSACng : null;
            using RSA? rsaPublicKey = tpmCertificate?.GetRSAPublicKey();
            bool useableCert = tpmCertificate?.HasPrivateKey == true && rsaPrivateKey is not null && rsaPublicKey is not null && rsaCngKey is not null && rsaCngKey?.Key.ExportPolicy == CngExportPolicies.None;
            tpmCertificate?.Dispose();
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
            await Bip39.GetWordValues(Bip39Dictionary);
            cbWordList = new()
            {
                cbWord1, cbWord2, cbWord3, cbWord4, cbWord5, cbWord6, cbWord7, cbWord8, cbWord9, cbWord10, cbWord11, cbWord12, cbWord13, cbWord14, cbWord15, cbWord16, cbWord17, cbWord18, cbWord19, cbWord20, cbWord21, cbWord22, cbWord23, cbWord24
            };
            for (int i = 0; i < 24; ++i)
            {
                InitComboBoxSeedWord(cbWordList[i]);
                cbWordList[i].SelectedIndex = -1;
            }
        }

        private void RestoreSeedPhraseWindow_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (sender is not ComboBox cbWord)
            {
                return;
            }
            int? cbWordIndex = cbWordList?.IndexOf(cbWord);
            string propertyName = $"Word{cbWordIndex + 1:00}";
            typeof(Bip39SeedPhrase)?.GetProperty(propertyName)?.SetValue(NewSeedPhrase, cbWord.SelectedIndex);
            btnValidateSeedPhrase.Enabled = !NewSeedPhrase.HasErrors;
        }

        private void CbWord_Validating(object? sender, CancelEventArgs e)
        {
        if (sender is not ComboBox cbWord)
            {
                return;
            }
            btnDeriveAccountNode.Enabled = false;
            if (cbWord.SelectedIndex == -1)
            {
                int? cbWordIndex = cbWordList?.IndexOf(cbWord);
                string propertyName = $"Word{cbWordIndex + 1:00}";
                typeof(Bip39SeedPhrase)?.GetProperty(propertyName)?.SetValue(NewSeedPhrase, cbWord.SelectedIndex);
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
            if (cbWordList is null)
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
                    ValidationStatusMessage = "At least one word is blank or invalid.";
                    return;
                }
            }
            ValidationStatusMessage = "Validated.";
            ValidationStatusColor = SystemColors.WindowText;
            Bip39BinarySeed bip39BinarySeed = new(ref _newSeedPhrase);
            if (bip39BinarySeed.TryGetBinarySeed(_newSeedPhrase.HasEmptyPassphrase ? null : Passphrase, out binarySeed))
            {
                ValidationStatusColor = Color.Green;
                ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
                btnDeriveAccountNode.Enabled = true;
                //Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(binarySeed, GlobalKeyRollovers);
                //Slip21ValidationNode validationNode = new(masterNode.GetChildNode(FirstLevelLabel.FirstLevelLabel).GetChildNode(GlobalKeyRollovers));
                //SeedDerivationPath = validationNode.DerivationPath;
                //OnPropertyChanged(nameof(SeedDerivationPath));
                //Slip21Node accountNode = masterNode.GetChildNode(FirstLevelLabel.FirstLevelLabel).GetChildNode(GlobalKeyRollovers).GetChildNode(AccountID).GetChildNode(AccountKeyRollovers);
                //Slip21ValidationNode accountValidationNode = new(accountNode);
                //AccountDerivationPath = accountValidationNode.DerivationPath;
                //OnPropertyChanged(nameof(AccountDerivationPath));
                //validationNode.FingerprintingStarted += new EventHandler<bool>((sender, e) =>
                //{
                //    if (e)
                //    {
                //        SeedValidationFingerprint = "Calculating...";
                //        OnPropertyChanged(nameof(SeedValidationFingerprint));
                //    }
                //});
                //validationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
                //{
                //    if (e)
                //    {
                //        SeedValidationFingerprint = validationNode.Fingerprint ?? string.Empty;
                //        OnPropertyChanged(nameof(SeedValidationFingerprint));
                //        accountValidationNode.CalculateFingerprint();
                //    }
                //});
                //accountValidationNode.FingerprintingStarted += new EventHandler<bool>((sender, e) =>
                //{
                //    if (e)
                //    {
                //        AccountValidationFingerprint = "Calculating...";
                //        OnPropertyChanged(nameof(AccountValidationFingerprint));
                //    }
                //});
                //accountValidationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
                //{
                //    if (e)
                //    {
                //        AccountValidationFingerprint = accountValidationNode.Fingerprint ?? string.Empty;
                //        OnPropertyChanged(nameof(AccountValidationFingerprint));
                //    }
                //});
                //validationNode.CalculateFingerprint();
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

        private void btnDeriveAccountNode_Click(object sender, EventArgs e)
        {
            ResetFingerprintDisplay();

            if (binarySeed == null)
            {
                return;
            }

            if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate, true))
            {
                statusLabel.Text = "Certificate/Key error";
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
                    validTpmCert = tpmCertificate?.HasPrivateKey == true && rsaPrivateKey is not null && rsaPublicKey is not null && rsaCngKey is not null && rsaCngKey?.Key.ExportPolicy == CngExportPolicies.None;
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
            }

            if (!validTpmCert)
            {
                statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
                LockSeedPhrase(true);
                btnValidateSeedPhrase.Enabled = false;
                btnDeriveAccountNode.Enabled = false;
                Cleanup();
                return;
            }
            if (rsaPublicKey is null)
            {
                statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) does not have a public key";
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
                encryptedLeft = rsaPublicKey.Encrypt(accountNode.Left.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            // RSACng.Encrypt (ArgumentNullException): arguments data and/or padding are null
            // RSACng.Encrypt (CryptographicException): argument padding has Mode property that is not Pkcs1 or Oaep
            catch (Exception)
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
            // Convert.ToHexString (ArgumentNullException): argument inArray is null
            // Convert.ToHexString (ArgumentOutOfRangeException): argument inArray is too large to be encoded
            catch (Exception)
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
            validationNode.FingerprintingStarted += new EventHandler<bool>((sender, e) =>
            {
                if (e)
                {
                    tbSeedFingerprint.Text = "Calculating...";
                }
            });
            validationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
            {
                if (e)
                {
                    tbSeedFingerprint.Text = validationNode.Fingerprint ?? string.Empty;
                    accountValidationNode.CalculateFingerprint();
                    if (slip21NodeEncrypted != null)
                    {
                        slip21NodeEncrypted.GlobalFingerprint = validationNode.Fingerprint;
                    }
                }
            });
            accountValidationNode.FingerprintingStarted += new EventHandler<bool>((sender, e) =>
            {
                if (e)
                {
                    tbAccountFingerprint.Text = "Calculating...";
                }
            });
            accountValidationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
            {
                if (e)
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
                        string accountFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.AccountFingerprint));
                        using StreamWriter file = new(Path.Combine(thisAppDataFolder, $"{accountFingerprintHex}.blob"), false, Encoding.UTF8, 4096);
                        StringBuilder nodeBackupData = new();
                        nodeBackupData.Append(slip21NodeEncrypted.SignablePart).Append('\x001E').Append(slip21NodeEncrypted.RSASignature);
                        file.WriteAsync(nodeBackupData.ToString());
                        file.Close();
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
