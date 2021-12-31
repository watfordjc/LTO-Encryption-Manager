using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
    /// <summary>
    /// Interaction logic for AddSeedPhraseWindow.xaml
    /// </summary>
    public partial class AddSeedPhraseWindow : Window, INotifyPropertyChanged
    {
        private IEnumerable<string>? bip0039Dictionary;
        public BIP0039.SeedPhrase? NewSeedPhrase { get; set; } = new();
        public bool ValidationInProgress { get; set; }
        public Brush? ValidateButtonBorderBrush { get; set; } = Brushes.Transparent;
        private readonly Argon2id argon2id = new();
        private Argon2idHashResult? argon2IdHashResult;

        public event PropertyChangedEventHandler? PropertyChanged;

        public AddSeedPhraseWindow()
        {
            Loaded += AddSeedPhrase_Loaded;
            InitializeComponent();
        }

        private async void AddSeedPhrase_Loaded(object sender, RoutedEventArgs e)
        {
            bip0039Dictionary = await Wallet.Bip0039.GetWordValues();
            DataContext = bip0039Dictionary;
            validateSeedPhrase.Click += ValidateSeedPhrase_Click;
            if (NewSeedPhrase is not null)
            {
                NewSeedPhrase.PropertyChanged += NewSeedPhrase_PropertyChanged;
            }
        }

        private void NewSeedPhrase_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            ValidateButtonBorderBrush = Brushes.Transparent;
            OnPropertyChanged("ValidateButtonBorderBrush");
            validationMessage.Text = string.Empty;
        }

        private async void ValidateSeedPhrase_Click(object sender, RoutedEventArgs e)
        {
            if (ValidationInProgress)
            {
                return;
            }

            DerivationPath.Text = string.Empty;
            ValidationFingerprint.Text = string.Empty;
            ValidationInProgress = true;
            OnPropertyChanged("ValidationInProgress");
            bool validationFailed = false;
            string? validationErrorMessage = null;
            string[]? seedPhraseWords = NewSeedPhrase?.Words;
            if (seedPhraseWords is null)
            {
                ValidateButtonBorderBrush = validationFailed ? Brushes.Red : Brushes.Green;
                OnPropertyChanged("ValidateButtonBorderBrush");
                validationMessage.Text = $"Seed Phrase is not {NewSeedPhrase?.Length} words long or contains words not in the BIP-0039 American English dictionary.";
                ValidationInProgress = false;
                OnPropertyChanged("ValidationInProgress");
                return;
            }
            try
            {
                _ = Wallet.Bip0039.GetEntropyBytesFromSeedWords(ref seedPhraseWords);
            }
            catch (ArgumentException ae)
            {
                validationErrorMessage = ae.Message;
                validationFailed = true;
                ValidateButtonBorderBrush = Brushes.Red;
                OnPropertyChanged("ValidateButtonBorderBrush");
                validationMessage.Text = string.Concat(validationErrorMessage);
                ValidationInProgress = false;
                OnPropertyChanged("ValidationInProgress");
                return;
            }
            if (!validationFailed)
            {
                ValidateButtonBorderBrush = Brushes.Green;
                OnPropertyChanged("ValidateButtonBorderBrush");
                validationMessage.Text = "Seed Phrase is Valid";
            }
            byte[] binarySeed = Wallet.Bip0039.GetBinarySeedFromSeedWords(ref seedPhraseWords, HasEmptyPassword.IsChecked == true ? string.Empty : Passphrase.Password);
            
            string? firstLevelLabel = (FirstLevelLabel.SelectedItem as ComboBoxItem)?.Tag.ToString();
            if (firstLevelLabel == null)
            {
                DerivationPath.Text = "First Level Label value does not have a Tag attribute.";
            }
            if (string.IsNullOrEmpty(GlobalKeyRollovers.Text))
            {
                GlobalKeyRollovers.Text = "0";
            }
            if (firstLevelLabel != null && !validationFailed)
            {
                DerivationPath.Text = string.Concat("m", "/\"", firstLevelLabel, "\"", "/\"", GlobalKeyRollovers.Text, "\"", "/\"uk.johncook.slip-0021.key-validation\"", "/\"", GlobalKeyRollovers.Text, "\"");

                byte[] masterNodeDerivationKey = new byte[32];
                byte[] validationNodeMessage = new byte[32];
                byte[] validationNodeSalt = new byte[16];
                GetNodes();

                void GetNodes()
                {
                    Wallet.Slip0021Node masterNode = Wallet.Slip0021.GetMasterNodeFromBinarySeed(binarySeed);
                    masterNodeDerivationKey = masterNode.Left.ToArray();
                    Trace.WriteLine($"m: {BitConverter.ToString(masterNode.Right.ToArray())}");
                    Wallet.Slip0021Node validationNode = masterNode.GetChildNode(firstLevelLabel).GetChildNode(GlobalKeyRollovers.Text).GetChildNode("uk.johncook.slip-0021.key-validation").GetChildNode(GlobalKeyRollovers.Text);
                    // The password/message to hash shall be the right half of the validation node... in Z85 encoding.
                    validationNodeMessage = validationNode.Right.ToArray();
                    // RFC 9160 Recommendation 1 means the length of the salt is already defined as 16 bytes.
                    // These 16 bytes shall be the first 128 bits of the left half of the validation node.
                    validationNodeSalt = validationNode.Left.Slice(0, 16).ToArray();
                    masterNode.Clear();
                    validationNode.Clear();
                }
                if (Wallet.Z85.TryGetEncodedBytes(validationNodeMessage, out byte[]? password))
                {
                    ValidationFingerprint.Text = "Calculating...";
                    argon2IdHashResult = await Task.Run(() => Wallet.Argon2id.GetKeyValidationHash(argon2id, password, validationNodeSalt, 32)).ConfigureAwait(true);
                    Trace.WriteLine(BitConverter.ToString(argon2IdHashResult.HashBytes));
                    if (Wallet.Z85.TryGetEncodedBytes(argon2IdHashResult.HashBytes, out byte[]? z85Hash))
                    {
                        Trace.WriteLine(Encoding.UTF8.GetString(z85Hash));
                        ValidationFingerprint.Text = Encoding.UTF8.GetString(z85Hash);
                    }
                }

                //Wallet.Bip0032MasterNode bitcoinMasterNode = Wallet.Bip0032.GetMasterNodeFromBinarySeed(binarySeed);
                //if (!bitcoinMasterNode.MasterChainCodeValid)
                //{
                //    validationFailed = true;
                //    validateSeedPhrase.BorderThickness = new(3);
                //    validateSeedPhrase.BorderBrush = Brushes.Red;
                //    validationMessage.Text = "Seed Phrase generates an invalid Bitcoin master node.";
                //}

                //bitcoinMasterNode.Clear();
                ValidationInProgress = false;
                OnPropertyChanged("ValidationInProgress");
            }
            
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
