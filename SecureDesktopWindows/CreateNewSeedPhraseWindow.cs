using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
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

        public class Slip21NodeEncrypted
        {
            /// <summary>
            /// The left 32 bytes of the node (the derivation key), encrypted with RSA key and encoded as hexadecimal
            /// </summary>
            public string EncryptedLeftHex { get; }
            public string DerivationPath { get; init; }
            public string GlobalKeyRolloverCount { get; init; }
            public string? GlobalFingerprint { get; set; }
            public string? AccountFingerprint { get; set; }
            public string SignablePart
            {
                get
                {
                    StringBuilder sb = new();
                    sb.Append(EncryptedLeftHex).Append('\x001F').Append(DerivationPath).Append('\x001F').Append(GlobalKeyRolloverCount);
                    if (GlobalFingerprint != null)
                    {
                        sb.Append('\x001F').Append(GlobalFingerprint);
                    }
                    if (AccountFingerprint != null)
                    {
                        sb.Append('\x001F').Append(AccountFingerprint);
                    }
                    return sb.ToString();
                }
            }
            public string? RSASignature { get; set; }

            public Slip21NodeEncrypted(string encryptedLeftHex, string derivationPath, string globalKeyRolloverCount)
            {
                EncryptedLeftHex = encryptedLeftHex;
                DerivationPath = derivationPath;
                GlobalKeyRolloverCount = globalKeyRolloverCount;
            }
        }

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

        private bool ValidCertificateExists()
        {
            X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = my.Certificates.Find(X509FindType.FindBySubjectName, "LTO Encryption Manager", true);
            bool useableCert = certificates.Count == 1;
            if (useableCert)
            {
                X509Certificate2 tpmCertificate = certificates[0];
                RSACng? rsaKey = (RSACng?)tpmCertificate.GetRSAPrivateKey();
                RSACng? rsaPubKey = (RSACng?)tpmCertificate.GetRSAPublicKey();
                if (!tpmCertificate.HasPrivateKey || rsaKey == null || rsaPubKey == null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
                {
                    useableCert = false;
                }
            }
            my.Close();
            return useableCert;
        }

        private void BtnGenerateSeed_Click(object sender, EventArgs e)
        {
            lblSeedHex1.Text = string.Empty;
            lblSeedHex2.Text = string.Empty;
            lblSeedHex3.Text = string.Empty;
            lblSeedHex4.Text = string.Empty;
            tbSeedFingerprint.Text = string.Empty;
            tbAccountFingerprint.Text = string.Empty;

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
                Tpm2 tpm = new(tpmDevice);

                X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
                my.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificates = my.Certificates.Find(X509FindType.FindBySubjectName, "LTO Encryption Manager", true);
                if (validTpmCert)
                {
                    X509Certificate2 tpmCertificate = certificates[0];
                    RSACng? rsaKey = (RSACng?)tpmCertificate.GetRSAPrivateKey();
                    RSACng? rsaPubKey = (RSACng?)tpmCertificate.GetRSAPublicKey();
                    if (!tpmCertificate.HasPrivateKey || rsaKey == null || rsaPubKey == null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
                    {
                        validTpmCert = false;
                        statusLabel.Text = "Error: TPM-backed user certificate (CN=LTO Encryption Manager) not found";
                        btnGenerateSeed.Enabled = false;
                        btnDeriveAccountNode.Enabled = false;
                    }
                    else
                    {
                        byte[] entropyBytes = tpm.GetRandom(32);
                        //Array.Clear(SeedBytes, 0, SeedBytes.Length);
                        //byte[] entropyBytes = Convert.FromHexString("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f");
                        string seedMnemonic = Bip39.GetMnemonicFromEntropy(BitConverter.ToString(entropyBytes).Replace("-", "").ToLower(CultureInfo.InvariantCulture));
                        Array.Clear(entropyBytes, 0, entropyBytes.Length);
                        string[] seedMnemonicSplit = seedMnemonic.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        binarySeed = Bip39.GetBinarySeedFromSeedWords(ref seedMnemonicSplit, null);
                        lblSeedHex1.Text = seedMnemonicSplit.Length >= 6 ? string.Format("{0} {1} {2} {3} {4} {5}", seedMnemonicSplit) : string.Empty;
                        lblSeedHex2.Text = seedMnemonicSplit.Length >= 12 ? string.Format("{6} {7} {8} {9} {10} {11}", seedMnemonicSplit) : string.Empty;
                        lblSeedHex3.Text = seedMnemonicSplit.Length >= 18 ? string.Format("{12} {13} {14} {15} {16} {17}", seedMnemonicSplit) : string.Empty;
                        lblSeedHex4.Text = seedMnemonicSplit.Length >= 24 ? string.Format("{18} {19} {20} {21} {22} {23}", seedMnemonicSplit) : string.Empty;
                        statusLabel.Text = "Success. Write down the new BIP39 recovery seed and store it securely, then derive the account node.";
                        btnDeriveAccountNode.Enabled = validTpmCert;
                    }
                }
                my.Close();

                //
                // Clean up.
                // 
                tpm.Dispose();
            }
            catch (Exception ex)
            {
                statusLabel.Text = $"Exception occurred: {ex.Message}";
                binarySeed = null;
                lblSeedHex1.Text = string.Empty;
                lblSeedHex2.Text = string.Empty;
                lblSeedHex3.Text = string.Empty;
                lblSeedHex4.Text = string.Empty;
            }
        }

        private void BtnDeriveAccountNode_Click(object sender, EventArgs e)
        {
            tbSeedFingerprint.Text = string.Empty;
            tbAccountFingerprint.Text = string.Empty;

            if (binarySeed == null)
            {
                return;
            }

            X509Store my = new(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = my.Certificates.Find(X509FindType.FindBySubjectName, "LTO Encryption Manager", true);
            bool useableCert = certificates.Count == 1;
            X509Certificate2? tpmCertificate;
            RSACng? rsaKey = null;
            RSACng? rsaPubKey = null;
            if (useableCert)
            {
                tpmCertificate = certificates[0];
                rsaKey = (RSACng?)tpmCertificate.GetRSAPrivateKey();
                rsaPubKey = (RSACng?)tpmCertificate.GetRSAPublicKey();
                if (!tpmCertificate.HasPrivateKey || rsaKey == null || rsaPubKey == null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
                {
                    useableCert = false;
                }
            }

            string firstLevelLabel = uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Properties.Resources.slip21_schema_lto_aes256gcm;
            Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(binarySeed, tbGlobalRollovers.Text);
            Slip21Node globalNode = masterNode.GetChildNode(firstLevelLabel).GetChildNode(tbGlobalRollovers.Text);
            Slip21ValidationNode validationNode = new(globalNode);
            Slip21Node accountNode = masterNode.GetChildNode(firstLevelLabel).GetChildNode(tbGlobalRollovers.Text).GetChildNode(tbAccount.Text).GetChildNode(tbAccountRollovers.Text);
            Slip21NodeEncrypted? slip21NodeEncrypted = null;
            if (useableCert && rsaPubKey != null)
            {
                byte[] encryptedLeft = rsaPubKey.Encrypt(accountNode.Left.ToArray(), RSAEncryptionPadding.Pkcs1);
                string encryptedLeftHex = Convert.ToHexString(encryptedLeft);
                slip21NodeEncrypted = new(encryptedLeftHex, accountNode.DerivationPath, accountNode.GlobalKeyRolloverCount);
                statusLabel.Text = slip21NodeEncrypted.SignablePart[512..].Replace('\x001F', '|');
            }
            Slip21ValidationNode accountValidationNode = new(accountNode);
            my.Close();
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
                    if (rsaKey != null && slip21NodeEncrypted != null && slip21NodeEncrypted.GlobalFingerprint != null && accountValidationNode.Fingerprint != null)
                    {
                        slip21NodeEncrypted.AccountFingerprint = accountValidationNode.Fingerprint;
                        try
                        {
                            statusLabel.Text = "Signing SLIP21 node data...";
                            byte[] nodeDataSigned = rsaKey.SignData(Encoding.UTF8.GetBytes(slip21NodeEncrypted.SignablePart), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            slip21NodeEncrypted.RSASignature = Convert.ToHexString(nodeDataSigned);
                            statusLabel.Text = $"Signature length: {slip21NodeEncrypted.RSASignature.Length} bytes";
                            string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                            string globalFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.GlobalFingerprint));
                            string thisAppDataFolder = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts", globalFingerprintHex);
                            if (!Directory.Exists(thisAppDataFolder))
                            {
                                Directory.CreateDirectory(thisAppDataFolder);
                            }
                            string accountFingerprintHex = Convert.ToHexString(Encoding.UTF8.GetBytes(slip21NodeEncrypted.AccountFingerprint));
                            using StreamWriter file = new(Path.Combine(thisAppDataFolder, $"{accountFingerprintHex}.blob"), false, Encoding.UTF8, 4096);
                            StringBuilder nodeBackupData = new();
                            nodeBackupData.Append(slip21NodeEncrypted.SignablePart).Append('\x001E').Append(slip21NodeEncrypted.RSASignature);
                            file.WriteAsync(nodeBackupData.ToString());
                            file.Close();
                            DialogResult = DialogResult.OK;
                            Dispose();
                        }
                        catch (Exception ex)
                        {
                            statusLabel.Text = $"Derived node signing error: {ex.Message}";
                        }

                    }
                }
            });
            validationNode.CalculateFingerprint();
        }
    }
}
