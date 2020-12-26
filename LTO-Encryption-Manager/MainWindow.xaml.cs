﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace LTO_Encryption_Manager
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

        private byte[] SeedWordsToEntropyBytes(string[] seedWords)
        {
            // An int array to store the seed word values
            int[] wordlistValues = new int[seedWords.Length];
            // Convert the seed words to integers
            for (int currentWord = 0; currentWord < wordlistValues.Length; currentWord++)
            {
                wordlistValues[currentWord] = BIP_0039_Dictionaries.en_US.IntFromWord(seedWords[currentWord]);
            }

            // Each seed word represents 11 bits
            int seedLength = wordlistValues.Length * 11;
            // There is a checksum bit for every 32 bits of entropy - 11 * 32 = 352
            int checksumLength = (seedLength / 352 * 32) + (seedLength % 32);
            // Calculate and validate the entropy length (in bits)
            int entropyLength = seedLength - checksumLength;
            if (entropyLength % 32 != 0)
            {
                throw new ArgumentException("Entropy from seed must be a multiple of 32 bits.");
            }

            // Entropy length in bytes
            int entropyLengthBytes = entropyLength / 8;
            // An int array to store the entropy
            int[] entropyByteInts = new int[entropyLengthBytes];
            // An int array to store the checksum
            int[] seedChecksumByteInts = new int[checksumLength / 8 + 1];

            // Track where we are in the entropy byte array
            int currentEntropyByte = 0;
            // Track where we are in the current entropy byte
            int currentEntropyBit = 0;
            // Track where we are in the checksum byte array
            int currentChecksumByte = 0;
            // Track where we are in the current checksum byte
            int currentChecksumBit = 0;
            // Extract the bits from the BIP-39 word value array
            for (int currentWord = 0; currentWord < wordlistValues.Length; currentWord++)
            {
                // Get the bits from the word
                for (int i = 0; i < 11; i++)
                {
                    // Check if this bit belongs to entropy bytes
                    if ((currentWord * 11 + i) < entropyLength)
                    {
                        // If the current bit should be a 1, make it a 1
                        if ((wordlistValues[currentWord] & (1 << (10 - i))) != 0)
                        {
                            entropyByteInts[currentEntropyByte] |= 1 << (7 - currentEntropyBit);
                        }
                        // Move to next bit in the current byte
                        currentEntropyBit++;
                        // Move to next byte if there are no bits left in the current byte
                        if (currentEntropyBit % 8 == 0)
                        {
                            currentEntropyByte++;
                            currentEntropyBit = 0;
                        }
                    }
                    else
                    {
                        // If the current bit should be a 1, make it a 1
                        if ((wordlistValues[currentWord] & (1 << (10 - i))) != 0)
                        {
                            seedChecksumByteInts[currentChecksumByte] |= 1 << (7 - currentChecksumBit);
                        }
                        // Move to next bit in the current byte
                        currentChecksumBit++;
                        // Move to next byte if there are no bits left in the current byte
                        if (currentChecksumBit % 8 == 0)
                        {
                            currentChecksumByte++;
                            currentChecksumBit = 0;
                        }
                    }
                }
            }

            // Convert the entropy int array to a byte array
            byte[] entropyBytes = new byte[entropyLengthBytes];
            for (int i = 0; i < entropyByteInts.Length; i++)
            {
                entropyBytes[i] = (byte)entropyByteInts[i];
            }
            Array.Clear(entropyByteInts, 0, entropyByteInts.Length);

            // Convert the checksum int array to a byte array
            byte[] seedChecksumBytes = new byte[checksumLength / 8 + 1];
            for (int i = 0; i < seedChecksumByteInts.Length; i++)
            {
                seedChecksumBytes[i] = (byte)seedChecksumByteInts[i];
            }
            Array.Clear(seedChecksumByteInts, 0, seedChecksumByteInts.Length);

            // Create a SHA256 instance
            SHA256 sha256 = SHA256.Create();
            // Calculate and store the checksum hash bytes
            byte[] checksumBytes = sha256.ComputeHash(entropyBytes);
            // Bit shift the last relevant byte in the hashsum for the final 1-8 checksum bits
            byte checksumBits = (byte)(checksumBytes[checksumLength / 8] << (7 - (checksumLength % 8)));
            // Verify the checksum bytes (if applicable)
            for (int i = 0; i < checksumLength / 8; i++)
            {
                if (seedChecksumBytes[i] != checksumBytes[i])
                {
                    Console.WriteLine("Checksum doesn't match.");
                }
            }
            // Verify the final 1-8 checksum bits
            if (checksumBits != seedChecksumBytes[^1])
            {
                Console.WriteLine("Checksum doesn't match.");
            }

            return entropyBytes;
        }

        private int[] EntropyHexToWordValues(String entropyHex)
        {
            // Convert entropy length from nibbles to bits
            int entropyLength = entropyHex.Length * 4;
            // Entropy length in bytes
            int entropyLengthBytes = entropyLength / 8;
            // BIP-0039 says entropy must be divisible by 32 bits (8 nibbles)
            if (entropyLength % 32 > 0)
            {
                throw new ArgumentException("Length of hexadecimal representation of mnemonic must be a multiple of 32 bits.", entropyHex);
            }
            // The number of checksum bits needed (makes length divisible by 11)
            int checksumLength = entropyLength / 32;

            // A byte array to store the entropy
            byte[] entropyBytes = new byte[entropyLengthBytes];
            // Convert each 2-nibble byte from hex string to bytes
            for (int currentByte = 0; currentByte < entropyLengthBytes; currentByte++)
            {
                entropyBytes[currentByte] = Convert.ToByte(entropyHex.Substring(currentByte * 2, 2), 16);
            }

            // Create a SHA256 instance
            SHA256 sha256 = SHA256.Create();
            // Calculate and store the checksum hash bytes
            byte[] checksumBytes = sha256.ComputeHash(entropyBytes);

            // An integer array to store the 11-bit BIP-39 word values
            int[] wordlistValues = new int[(entropyLength + checksumLength) / 11];

            // Track where we are in the entropy byte array
            int currentEntropyByte = 0;
            // Track where we are in the current entropy byte
            int currentEntropyBit = 0;
            // Track where we are in the checksum byte array
            int currentChecksumByte = 0;
            // Track where we are in the current checksum byte
            int currentChecksumBit = 0;
            // Populate the BIP-39 word value array
            for (int currentWord = 0; currentWord < wordlistValues.Length; currentWord++)
            {
                // Clear the value of the new word
                wordlistValues[currentWord] = 0;
                // Fill the bits of the word
                for (int i = 0; i < 11; i++)
                {
                    // Check if this bit can come from the entropy bytes
                    if ((currentWord * 11 + i) < entropyLength)
                    {
                        // If the current bit should be a 1, make it a 1
                        if ((entropyBytes[currentEntropyByte] & (1 << (7 - currentEntropyBit))) != 0)
                        {
                            wordlistValues[currentWord] |= 1 << (10 - i);
                        }
                        // Move to next bit in the current byte
                        currentEntropyBit++;
                        // Move to next byte if there are no bits left in the current byte
                        if (currentEntropyBit % 8 == 0)
                        {
                            currentEntropyByte++;
                            currentEntropyBit = 0;
                        }
                    }
                    else
                    {
                        // If the current bit should be a 1, make it a 1
                        if ((checksumBytes[currentChecksumByte] & (1 << (7 - currentChecksumBit))) != 0)
                        {
                            wordlistValues[currentWord] |= 1 << (10 - i);
                        }
                        // Move to next bit in the current byte
                        currentChecksumBit++;
                        // Move to next byte if there are no bits left in the current byte
                        if (currentChecksumBit % 8 == 0)
                        {
                            currentChecksumByte++;
                            currentChecksumBit = 0;
                        }
                    }
                }
            }
            Array.Clear(entropyBytes, 0, entropyBytes.Length);
            Array.Clear(checksumBytes, 0, checksumBytes.Length);
            return wordlistValues;
        }

        private void TestButton_Click(object sender, RoutedEventArgs e)
        {
            int[] entropywithChecksum = EntropyHexToWordValues(MnemonicHexText.Text);
            StringBuilder sb = new StringBuilder();
            String separator = "";
            foreach (int i in entropywithChecksum)
            {
                sb.Append(separator);
                sb.Append(BIP_0039_Dictionaries.en_US.WordFromInt(i));
                separator = " ";
            }
            MnemonicText.Text = sb.ToString();
        }

        private void TestButton2_Click(object sender, RoutedEventArgs e)
        {
            byte[] entropyBytes = SeedWordsToEntropyBytes(MnemonicText.Text.Trim().Split(' '));
            MnemonicHexText.Text = BitConverter.ToString(entropyBytes).Replace("-", "").ToLower();
        }
    }
}
