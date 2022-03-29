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
        private static readonly Windows.Win32.Foundation.BOOL FALSE = (Windows.Win32.Foundation.BOOL)0;
        private static readonly Windows.Win32.Foundation.BOOL TRUE = (Windows.Win32.Foundation.BOOL)1;
        private string CurrentAccountDataFile { get; set; } = string.Empty;
        static Guid GUID_DEVINTERFACE_VOLUME = new("{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}");
        private Slip21NodeEncrypted? currentAccountSlip21Node;
        KeyAssociatedData? kad = null;

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
            btnCreateAccountNewRecoverySeed.Click += BtnCreateNewBip39Seed_Click;
            btnCreateAccountExistingRecoverySeed.Click += BtnCreateAccountExistingRecoverySeed_Click;
            cbGlobalFingerprints.SelectionChanged += CbGlobalFingerprints_SelectionChanged;
            cbAccountFingerprints.SelectionChanged += CbAccountFingerprints_SelectionChanged;
            btnTestAccount.Click += BtnTestAccount_Click;
            cbTapeDrives.SelectionChanged += CbTapeDrives_SelectionChanged;
            btnCalculateKAD.Click += BtnCalculateKAD_Click;
            btnCreateRsaKey.Click += BtnCreateRsaKey_Click;
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

        private void BtnCalculateKAD_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            tbKAD.Text = string.Empty;
            btnCalculateKAD.IsEnabled = false;
            if (currentAccountSlip21Node is null || currentAccountSlip21Node.RSASignature is null || string.IsNullOrEmpty(tbTapeLabel.Text) || string.IsNullOrEmpty(tbTapeKeyRollovers.Text))
            {
                btnCalculateKAD.IsEnabled = true;
                return;
            }
            if (uint.TryParse(tbTapeKeyRollovers.Text, out uint tapeRollovercount))
            {
                kad = new(currentAccountSlip21Node, tbTapeLabel.Text, tapeRollovercount);
            }
            else
            {
                btnCalculateKAD.IsEnabled = true;
                return;
            }

            if (!Utils.PKI.TryGetOrCreateRsaCertificate(out X509Certificate2? tpmCertificate, false))
            {
                tpmCertificate?.Dispose();
                btnCalculateKAD.IsEnabled = true;
                return;
            }
            using RSACng? rsaKey = (RSACng?)tpmCertificate.GetRSAPrivateKey();
            using RSACng? rsaPubKey = (RSACng?)tpmCertificate.GetRSAPublicKey();
            if (!tpmCertificate.HasPrivateKey || rsaKey == null || rsaPubKey == null || rsaKey.Key.ExportPolicy != CngExportPolicies.None)
            {
                tpmCertificate?.Dispose();
                btnCalculateKAD.IsEnabled = true;
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
                        Slip21ValidationNode tapeValidationNode = new(tapeNode);
                        tapeValidationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
                        {
                            if (e)
                            {
                                string tapeValidationFingerprint = tapeValidationNode.Fingerprint ?? string.Empty;
                                statusbarStatus.Content = string.Format("Key Authenticated Data generated");
                                btnTestAccount.IsEnabled = true;
                                kad.TapeFingerprint = tapeValidationFingerprint;
                                tbKAD.Text = kad.GetKAD();
                            }
                        });
                        statusbarStatus.Content = "Calculating Key Authenticated Data...";
                        tapeValidationNode.CalculateFingerprint(24);
                    }
                    catch (Exception ex)
                    {
                        Error = $"Decryption Error: {ex.Message}";
                        btnTestAccount.IsEnabled = true;
                    }
                }
            }
            tpmCertificate?.Dispose();
            btnCalculateKAD.IsEnabled = true;
        }

        private void TapeDriveSelected(TapeDrive? tapeDrive)
        {
            btnDetectTape.IsEnabled = true;
        }

        private void CbTapeDrives_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (e.AddedItems == null || e.AddedItems.Count == 0 || e.AddedItems[0] is not TapeDrive tapeDrive)
            {
                btnDetectTape.IsEnabled = false;
                return;
            }
            TapeDriveSelected(tapeDrive);
        }

        public class TapeDrive
        {
            public string DeviceId { get; set; } = string.Empty;
            public string Path => string.Concat(@"\\?\", DeviceId.Replace("\\", "#"), "#{", GUID_DEVINTERFACE_VOLUME.ToString(), "}");
            public string Caption { get; set; } = string.Empty;
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
                tbKAD.Text = Convert.ToHexString(asnEncodedData.RawData);
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
                            Trace.WriteLine(string.Format("RSA-signed account node fingerprint: {0}. Fingerprint derived from decrypted account derivation key: {1}. TPM-backed keypair {2} validation check. Global node fingerprint: {3}", nodeDataSplit[4], accountValidationFingerprint, accountFingerprintMatches ? "passes" : "fails", nodeDataSplit[3]));
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

        private void AccountFingerprintChanged(string accountFingerprint)
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

        private void CbAccountFingerprints_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (e.AddedItems == null || e.AddedItems.Count == 0 || cbGlobalFingerprints.SelectedIndex == -1 || e.AddedItems[0] is not string accountFingerprint)
            {
                return;
            }
            AccountFingerprintChanged(accountFingerprint);
        }

        private void GlobalFingerprintChanged(string globalFingerprint)
        {
            string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            try
            {
                string accountDirectoriesBase = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts", Convert.ToHexString(Encoding.UTF8.GetBytes(globalFingerprint)));
                string[] accountFingerprintFiles = Directory.GetFiles(accountDirectoriesBase, "*.blob", SearchOption.TopDirectoryOnly);
                List<string> accountFingerprints = new();
                foreach (string file in accountFingerprintFiles)
                {
                    if (File.Exists(file))
                    {
                        FileInfo fileInfo = new(file);
                        accountFingerprints.Add(Encoding.UTF8.GetString(Convert.FromHexString(fileInfo.Name.Split('.')[0])));
                    }
                }
                cbAccountFingerprints.ItemsSource = accountFingerprints;
                Error = string.Empty;
                if (accountFingerprints.Count == 1)
                {
                    cbAccountFingerprints.SelectedIndex = 0;
                    AccountFingerprintChanged(accountFingerprints[0]);
                }
            }
            catch (Exception ex)
            {
                Error = $"Account loading error: {ex.Message}";
            }
        }

        private void CbGlobalFingerprints_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (e.AddedItems == null || e.AddedItems.Count == 0 || e.AddedItems[0] is not string globalFingerprint)
            {
                return;
            }
            GlobalFingerprintChanged(globalFingerprint);
        }

        private void BtnCreateAccountExistingRecoverySeed_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            //StartupWindow startupWindow = new();
            //startupWindow.ShowDialog();
            if (SecureBootEnabled && TpmSupported)
            {
                ShowSecureWindow(SecureWindowTypes.RestoreSeedPhraseWindow);
            }
        }

        private void BtnCreateNewBip39Seed_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            if (SecureBootEnabled && TpmSupported)
            {
                ShowSecureWindow(SecureWindowTypes.CreateNewSeedPhraseWindow);
            }
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
            EnumerateTapeDrives();
            EnableHpeLtfsTools();
        }

        private void EnumerateTapeDrives()
        {
            try
            {
                string appDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string accountDirectoriesBase = Path.Combine(appDataFolder, "John Cook UK", "LTO-Encryption-Manager", "Accounts");
                string[] globalFingerprintDirectories = Directory.GetDirectories(accountDirectoriesBase, "*", SearchOption.TopDirectoryOnly);
                List<string> globalFingerprints = new();
                foreach (string dir in globalFingerprintDirectories)
                {
                    if (Directory.Exists(dir))
                    {
                        DirectoryInfo dirInfo = new(dir);
                        globalFingerprints.Add(Encoding.UTF8.GetString(Convert.FromHexString(dirInfo.Name)));
                    }
                }
                cbGlobalFingerprints.ItemsSource = globalFingerprints;
                if (globalFingerprints.Count == 1)
                {
                    cbGlobalFingerprints.SelectedIndex = 0;
                    GlobalFingerprintChanged(globalFingerprints[0]);
                }
                string Namespace = @"root\cimv2";
                string ComputerName = "localhost";
                using DComSessionOptions cimSessionOptions = new()
                {
                    Timeout = TimeSpan.FromSeconds(30)
                };
                using CimSession cimSession = CimSession.Create(ComputerName, cimSessionOptions);
                IEnumerable<CimInstance> cimInstances = cimSession.QueryInstances(Namespace, "WQL", @"SELECT * FROM Win32_TapeDrive");
                List<TapeDrive> tapeDrives = new();
                foreach (CimInstance cimInstance in cimInstances)
                {
                    string? deviceId = cimInstance.CimInstanceProperties["DeviceID"].Value.ToString();
                    string? caption = cimInstance.CimInstanceProperties["Caption"].Value.ToString();
                    if (deviceId == null)
                    {
                        continue;
                    }
                    TapeDrive currentDrive = new();
                    currentDrive.DeviceId = deviceId;
                    currentDrive.Caption = caption ?? string.Empty;
                    tapeDrives.Add(currentDrive);
                    cimInstance.Dispose();
                }
                cbTapeDrives.ItemsSource = tapeDrives;
                if (cbTapeDrives.Items.Count == 1)
                {
                    cbTapeDrives.SelectedIndex = 0;
                    TapeDriveSelected(tapeDrives[0]);
                }
            }
            catch (Exception ex)
            {
                Error = ex.Message;
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
            if (Windows.Win32.PInvoke.SwitchDesktop(hSecureDesktop) == TRUE)
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
                EnumerateTapeDrives();
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

        private enum SecureWindowTypes
        {
            CreateNewSeedPhraseWindow = 0,
            RestoreSeedPhraseWindow = 1
        }

        private static void SecureDesktopThread(SafeHandle hSecureDesktop, SecureWindowTypes secureWindowType)
        {
            if (Windows.Win32.PInvoke.SetThreadDesktop(hSecureDesktop) == TRUE)
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
    }
}
