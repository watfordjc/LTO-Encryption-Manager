﻿using System;
using System.Security;
using System.Windows;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

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
            string[] mnemonicTextWords = MnemonicText.Text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? throw new ArgumentException("Unable to parse mnemonic seed.");

			// Turn BIP-0039 word array into byte array
			byte[] entropyBytes = Bip39.GetEntropyBytesFromSeedWords(ref mnemonicTextWords);
            if (entropyBytes.Length == 0)
            {
                throw new ArgumentException("Not a valid mnemonic seed.");
            }
            MnemonicHexText.Text = Utils.Encodings.ToHexString(entropyBytes);
            Array.Clear(entropyBytes, 0, entropyBytes.Length);

            // Turn BIP-0039 word array into BIP-0039 master seed
            SecureString testPassphrase = new();
            foreach (char c in "TREZOR")
            {
                testPassphrase.AppendChar(c);
            }
            testPassphrase.MakeReadOnly();
            byte[] seedBytes = Bip39.GetBinarySeedFromSeedWords(ref mnemonicTextWords, testPassphrase);
            testPassphrase.Clear();
            testPassphrase.Dispose();
            Array.Clear(mnemonicTextWords, 0, mnemonicTextWords.Length);
            SeedHex.Text = Utils.Encodings.ToHexString(seedBytes);

            // SLIP-0021 master node
            Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(seedBytes, "0");
            Array.Clear(seedBytes, 0, seedBytes.Length);
            MasterDerivationHex.Text = Utils.Encodings.ToHexString(masterNode.Left);
            MasterKeyHex.Text = Utils.Encodings.ToHexString(masterNode.Right);

            // First SLIP-0021 documentation test node: m/"SLIP-0021"
            Slip21Node slip21Node = masterNode.GetChildNode("SLIP-0021");
            masterNode.Clear();
            Slip21KeyHex.Text = Utils.Encodings.ToHexString(slip21Node.Right);

            // Second test node: m/"SLIP-0021"/"Master encryption key"
            Slip21Node masterEncryptionNode = slip21Node.GetChildNode("Master encryption key");
            Slip21MasterEncryptionKeyHex.Text = Utils.Encodings.ToHexString(masterEncryptionNode.Right);
            masterEncryptionNode.Clear();

            // Third test node: m/"SLIP-0021"/"Authentication key"
            Slip21Node masterAuthNode = slip21Node.GetChildNode("Authentication key");
            Slip21AuthenticationKeyHex.Text = Utils.Encodings.ToHexString(masterAuthNode.Right);
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
