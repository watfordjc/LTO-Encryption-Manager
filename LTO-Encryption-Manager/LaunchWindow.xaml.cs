using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
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
        private readonly Windows.Win32.Foundation.BOOL TRUE = (Windows.Win32.Foundation.BOOL)1;
        private string CurrentAccountDataFile { get; set; } = string.Empty;
        static Guid GUID_DEVINTERFACE_VOLUME = new("{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}");

        public LaunchWindow()
        {
            InitializeComponent();
            Error = string.Empty;
            SecureBootEnabled = SecureBoot.IsEnabled();
            btnCreateAccountNewRecoverySeed.IsEnabled = _secureBootEnabled;
            TpmStatus = new();
            TpmStatus.Completed += TpmStatus_Completed;
            TpmStatus.Begin();
            Window.DataContext = this;
            btnCreateAccountNewRecoverySeed.Click += BtnCreateNewBip39Seed_Click;
            cbGlobalFingerprints.SelectionChanged += CbGlobalFingerprints_SelectionChanged;
            cbAccountFingerprints.SelectionChanged += CbAccountFingerprints_SelectionChanged;
            btnTestAccount.Click += BtnTestAccount_Click;
            cbTapeDrives.SelectionChanged += CbTapeDrives_SelectionChanged;
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
            using StreamReader streamReader = new(CurrentAccountDataFile, Encoding.UTF8, true, 4096);
            string nodeData = streamReader.ReadToEnd();
            streamReader.Close();

            string[] nodeDataSigSplit = nodeData.Split('\x001E');
            byte[] rsaSignature = Convert.FromHexString(nodeDataSigSplit[1]);
            string nodeDataSigned = nodeDataSigSplit[0];
            string[] nodeDataSplit = nodeDataSigned.Split('\x001F');
            byte[] nodeLeftDecrypted = Convert.FromHexString(nodeDataSplit[0]);

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
                else
                {
                    bool signatureValid = rsaPubKey.VerifyData(Encoding.UTF8.GetBytes(nodeDataSigned), rsaSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    if (signatureValid)
                    {
                        byte[] nodeBytes = new byte[64];
                        Array.Clear(nodeBytes, 0, 64);
                        try
                        {
                            statusbarStatus.Content = "Testing account key decryption...";
                            byte[] nodeLeft = rsaKey.Decrypt(nodeLeftDecrypted, RSAEncryptionPadding.Pkcs1);
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
                my.Close();
            }
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

        private void BtnCreateNewBip39Seed_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            if (SecureBootEnabled && TpmSupported)
            {
                ShowSecureWindow();
            }
        }

        private void TpmStatus_Completed(object? sender, bool e)
        {
            bool tpmSupported = true;
            if (sender is TpmStatus tpmStatus)
            {
                TpmStatus = tpmStatus;
            }
            else
            {
                return;
            }
            if (!SecureBootEnabled)
            {
                tpmSupported = false;
            }
            if (tpmStatus.HasTpm && tpmStatus.HasPcrBankAlgo.Contains(Tpm2Lib.TpmAlgId.Sha256))
            {
                if (!tpmStatus.SupportedAlgo.Contains(Tpm2Lib.TpmAlgId.Rsa))
                {
                    tpmSupported = false;
                }
                if (!tpmStatus.SupportedAlgo.Contains(Tpm2Lib.TpmAlgId.Aes))
                {
                    tpmSupported = false;
                }
            }
            else
            {
                tpmSupported = false;
            }
            TpmSupported = tpmSupported;

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
            DComSessionOptions cimSessionOptions = new()
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            CimSession cimSession = CimSession.Create(ComputerName, cimSessionOptions);
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
            }
            cbTapeDrives.ItemsSource = tapeDrives;
            if (cbTapeDrives.Items.Count == 1)
            {
                cbTapeDrives.SelectedIndex = 0;
                TapeDriveSelected(tapeDrives[0]);
            }
            EnableHpeLtfsTools();
        }

        private void EnableHpeLtfsTools()
        {
            string hpeLtfsCartridgeBrowserLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Cartridge Browser.lnk";
            if (File.Exists(hpeLtfsCartridgeBrowserLink))
            {
                void BtnStartLtfsCartridgeBrowser_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsCartridgeBrowserLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsCartridgeBrowser.Click += BtnStartLtfsCartridgeBrowser_Click;
                btnStartLtfsCartridgeBrowser.IsEnabled = true;
            }
            string hpeLtfsCheckWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Check Wizard.lnk";
            if (File.Exists(hpeLtfsCheckWizardLink))
            {
                void BtnStartLtfsCheckWizard_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsCheckWizardLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsCheckWizard.Click += BtnStartLtfsCheckWizard_Click;
                btnStartLtfsCheckWizard.IsEnabled = true;
            }
            string hpeLtfsConfiguratorLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Configurator.lnk";
            if (File.Exists(hpeLtfsConfiguratorLink))
            {
                void BtnStartLtfsConfigurator_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsConfiguratorLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsConfigurator.Click += BtnStartLtfsConfigurator_Click;
                btnStartLtfsConfigurator.IsEnabled = true;
            }
            string hpeLtfsConsoleLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Console.lnk";
            if (File.Exists(hpeLtfsConsoleLink))
            {
                void BtnStartLtfsConsole_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsConsoleLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsConsole.Click += BtnStartLtfsConsole_Click;
                btnStartLtfsConsole.IsEnabled = true;
            }
            string hpeLtfsFormatWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Format Wizard.lnk";
            if (File.Exists(hpeLtfsFormatWizardLink))
            {
                void BtnStartLtfsFormatWizard_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsFormatWizardLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsFormatWizard.Click += BtnStartLtfsFormatWizard_Click;
                btnStartLtfsFormatWizard.IsEnabled = true;
            }
            string hpeLtfsUnformatWizardLink = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\HPE\HPE StoreOpen Software\LTFS Unformat Wizard.lnk";
            if (File.Exists(hpeLtfsUnformatWizardLink))
            {
                void BtnStartLtfsUnformatWizard_Click(object sender, System.Windows.RoutedEventArgs e)
                {
                    Process process = new()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = hpeLtfsUnformatWizardLink,
                            UseShellExecute = true
                        }
                    };
                    process.Start();
                }
                btnStartLtfsUnformatWizard.Click += BtnStartLtfsUnformatWizard_Click;
                btnStartLtfsUnformatWizard.IsEnabled = true;
            }
        }

        private void BtnStartLtfsCheckWizard_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            throw new NotImplementedException();
        }

        private void ShowSecureWindow()
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
                    SecureDesktopThread(hSecureDesktop);
                });
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
                thread.Join();
                _ = Windows.Win32.PInvoke.SwitchDesktop(hOldDesktop);
                hSecureDesktop.Close();
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

        private void SecureDesktopThread(SafeHandle hSecureDesktop)
        {
            if (Windows.Win32.PInvoke.SetThreadDesktop(hSecureDesktop) == TRUE)
            {
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
                PlayUacSound();
                SecureDesktopWindows.CreateNewSeedPhraseWindow secureWindow = new();
                secureWindow.ShowDialog();
                Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        }
    }


    }
