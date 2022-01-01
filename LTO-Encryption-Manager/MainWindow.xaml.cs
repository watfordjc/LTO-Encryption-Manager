using System;
using System.Globalization;
using System.Windows;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Turn hexadecimal entropy into seed phrase
        /// </summary>
        private void ProcessEntropyHex()
        {
            MnemonicText.Text = Bip39.GetMnemonicFromEntropy(MnemonicHexText.Text);
            ProcessSeedWords();
        }

        /// <summary>
        /// Generate nodes and keys from seed phrase
        /// </summary>
        /// <remarks>
        /// <para>Security: Uses String instead of SecureString due to use of TextBox instead of PasswordBox - waiting for SensitiveData type.</para>
        /// <para>Security: Uses String[] instead of ReadOnlySpan&lt;char&gt;[] - waiting for Dictionary&lt;string, int&gt; to allow lookup by ReadOnlySpan&lt;char&gt;</para>
        /// </remarks>
        private void ProcessSeedWords()
        {
            // Split BIP-0039 mnemonic input into an array of BIP-0039 words
            string[] mnemonicTextWords = MnemonicText.Text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (mnemonicTextWords is null)
            {
                throw new ArgumentException("Unable to parse mnemonic seed.");
            }

            // Turn BIP-0039 word array into byte array
            byte[] entropyBytes = Bip39.GetEntropyBytesFromSeedWords(ref mnemonicTextWords);
            if (entropyBytes.Length == 0)
            {
                throw new ArgumentException("Not a valid mnemonic seed.");
            }
            MnemonicHexText.Text = Convert.ToHexString(entropyBytes.AsSpan()).ToLower(CultureInfo.InvariantCulture);
            Array.Clear(entropyBytes, 0, entropyBytes.Length);

            // Turn BIP-0039 word array into BIP-0039 master seed
            byte[] seedBytes = Bip39.GetBinarySeedFromSeedWords(ref mnemonicTextWords, "TREZOR");
            Array.Clear(mnemonicTextWords, 0, mnemonicTextWords.Length);
            SeedHex.Text = Convert.ToHexString(seedBytes.AsSpan()).ToLower(CultureInfo.InvariantCulture);

            // SLIP-0021 master node
            Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(seedBytes);
            Array.Clear(seedBytes, 0, seedBytes.Length);
            MasterDerivationHex.Text = Convert.ToHexString(masterNode.Left).ToLower(CultureInfo.InvariantCulture);
            MasterKeyHex.Text = Convert.ToHexString(masterNode.Right).ToLower(CultureInfo.InvariantCulture);

            // First SLIP-0021 documentation test node: m/"SLIP-0021"
            Slip21Node slip21Node = masterNode.GetChildNode("SLIP-0021");
            masterNode.Clear();
            Slip21KeyHex.Text = Convert.ToHexString(slip21Node.Right).ToLower(CultureInfo.InvariantCulture);

            // Second test node: m/"SLIP-0021"/"Master encryption key"
            Slip21Node masterEncryptionNode = slip21Node.GetChildNode("Master encryption key");
            Slip21MasterEncryptionKeyHex.Text = Convert.ToHexString(masterEncryptionNode.Right).ToLower(CultureInfo.InvariantCulture);
            masterEncryptionNode.Clear();

            // Third test node: m/"SLIP-0021"/"Authentication key"
            Slip21Node masterAuthNode = slip21Node.GetChildNode("Authentication key");
            Slip21AuthenticationKeyHex.Text = Convert.ToHexString(masterAuthNode.Right).ToLower(CultureInfo.InvariantCulture);
            masterAuthNode.Clear();
            slip21Node.Clear();
        }

        private void TestHexEntropyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessEntropyHex();
            }
            catch (ArgumentException ex)
            {
                _ = MessageBox.Show(ex.Message, "Invalid Entropy", MessageBoxButton.OK, MessageBoxImage.Asterisk, MessageBoxResult.OK);
            }
        }

        private void TestMnemonic_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ProcessSeedWords();
            }
            catch (ArgumentException ex)
            {
                _ = MessageBox.Show(ex.Message, "Invalid Mnemonic Seed", MessageBoxButton.OK, MessageBoxImage.Asterisk, MessageBoxResult.OK);
            }
        }

    }
}
