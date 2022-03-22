using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.BIP39Dictionaries;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
    public static class Bip39
    {
        public static IEnumerable<string> GetWordValue(int index)
        {
            if (AmericanEnglish.TryGetWordFromInt(index, out string? word))
            {
                yield return word;
            }
        }

        public static Task<List<string>> GetWordValues()
        {
            List<string> words = new();
            for (int i = 0; i < 2048; i++)
            {
                if (AmericanEnglish.TryGetWordFromInt(i, out string? word))
                {
                    words.Add(word);
                }
            }
            return Task.FromResult(words);
        }

        /// <summary>
        /// Convert some entropy to a BIP-0039 mnemonic seed.
        /// </summary>
        /// <param name="entropyHex">The entropy, in hexadecimal.</param>
        /// <returns>A BIP-0039 mnemonic seed.</returns>
        public static string GetMnemonicFromEntropy(ReadOnlySpan<char> entropyHex)
        {
            int[] entropywithChecksum = GetWordValuesFromEntropy(entropyHex);
            StringBuilder sb = new();
            string separator = "";
            foreach (int i in entropywithChecksum)
            {
                if (AmericanEnglish.TryGetWordFromInt(i, out string? word))
                {
                    _ = sb
                    .Append(separator)
                    .Append(word);
                    separator = " ";
                }
                else
                {
                    _ = sb.Clear();
                    Array.Clear(entropywithChecksum, 0, entropywithChecksum.Length);
                    throw new NotImplementedException($"The BIP-0039 en_US dictionary does not contain a word at index {i}.");
                }
            }
            string mnemonicString = sb.ToString();
            _ = sb.Clear();
            Array.Clear(entropywithChecksum, 0, entropywithChecksum.Length);
            return mnemonicString;
        }

        /// <summary>
        /// Convert some entropy to a list of BIP-0039 word list positions.
        /// </summary>
        /// <param name="entropyHex">The entropy, in hexadecimal.</param>
        /// <returns>A list of BIP-0039 word list positions (zero-based numbering).</returns>
        public static int[] GetWordValuesFromEntropy(ReadOnlySpan<char> entropyHex)
        {
            // Convert entropy length from nibbles to bits
            int entropyLength = entropyHex.Length * 4;
            // BIP-0039 says entropy must be divisible by 32 bits (8 nibbles)
            if (entropyLength == 0 || entropyLength % 32 > 0)
            {
                throw new ArgumentException("Length of hexadecimal representation of mnemonic seed must be a multiple of 32 bits.");
            }
            // The number of checksum bits needed (makes length divisible by 11)
            int checksumLength = entropyLength / 32;

            // Convert the hexadecimal representation of the entropy to a byte array
            byte[] entropyBytes = Convert.FromHexString(entropyHex);

            // Create a SHA256 instance
            using SHA256 sha256 = SHA256.Create();
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
            // Clear arrays
            Array.Clear(entropyBytes, 0, entropyBytes.Length);
            Array.Clear(checksumBytes, 0, checksumBytes.Length);
            return wordlistValues;
        }

        /// <summary>
        /// Convert BIP-0039 mnemonic seed words to the original entropy used to create the mnemonic seed.
        /// </summary>
        /// <param name="seedWords">An array of BIP-0039 mnemonic words.</param>
        /// <returns>The binary representation of the original entropy.</returns>
        public static byte[] GetEntropyBytesFromSeedWords(ref string[] seedWords)
        {
            if (seedWords.Length == 0)
            {
                throw new ArgumentException($"No mnemonic seed entered.");
            }
            // An int array to store the seed word values
            int?[] wordlistValues = new int?[seedWords.Length];
            // Convert the seed words to integers
            for (int currentWord = 0; currentWord < wordlistValues.Length; currentWord++)
            {
                if (AmericanEnglish.TryGetIntFromWord(seedWords[currentWord], out int? value))
                {
                    wordlistValues[currentWord] = value;
                }
                else
                {
                    Array.Clear(wordlistValues, 0, wordlistValues.Length);
                    throw new ArgumentException($"The word '{seedWords[currentWord]}' is not in the BIP-0039 en_US dictionary.");
                }
            }

            // Each seed word represents 11 bits
            int seedLength = wordlistValues.Length * 11;
            // There is a checksum bit for every 32 bits of entropy - 11 * 32 = 352
            int checksumLength = (seedLength / 352 * 32) + (seedLength % 32);
            // Calculate and validate the entropy length (in bits)
            int entropyLength = seedLength - checksumLength;
            if (entropyLength % 32 != 0)
            {
                Array.Clear(wordlistValues, 0, wordlistValues.Length);
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
            // Clear array
            Array.Clear(wordlistValues, 0, wordlistValues.Length);

            // Convert the entropy int array to a byte array
            byte[] entropyBytes = new byte[entropyLengthBytes];
            for (int i = 0; i < entropyByteInts.Length; i++)
            {
                entropyBytes[i] = (byte)entropyByteInts[i];
            }
            // Clear array
            Array.Clear(entropyByteInts, 0, entropyByteInts.Length);

            // Convert the checksum int array to a byte array
            byte[] seedChecksumBytes = new byte[checksumLength / 8 + 1];
            for (int i = 0; i < seedChecksumByteInts.Length; i++)
            {
                seedChecksumBytes[i] = (byte)seedChecksumByteInts[i];
            }
            // Clear array
            Array.Clear(seedChecksumByteInts, 0, seedChecksumByteInts.Length);

            // Create a SHA256 instance
            using SHA256 sha256 = SHA256.Create();
            // Calculate and store the checksum hash bytes
            byte[] checksumBytes = sha256.ComputeHash(entropyBytes);
            // Bit shift the last relevant byte in the hashsum for the final 1-8 checksum bits
            byte checksumBits = (byte)(checksumBytes[checksumLength / 8] >> (byte)(8 - (checksumLength % 8)));
            // Bit shift the last byte in the seed checksum for the final 1-8 checksum bits
            byte seedChecksumBits = (byte)(seedChecksumBytes[checksumLength / 8] >> (byte)(8 - (checksumLength % 8)));
            // Verify the checksum bytes (if applicable)
            for (int i = 0; i < checksumLength / 8; i++)
            {
                if (seedChecksumBytes[i] != checksumBytes[i])
                {
                    // Clear arrays and throw exception
                    Array.Clear(entropyBytes, 0, entropyBytes.Length);
                    Array.Clear(seedChecksumBytes, 0, seedChecksumBytes.Length);
                    Array.Clear(checksumBytes, 0, checksumBytes.Length);
                    throw new ArgumentException("Checksum doesn't match.");
                }
            }
            // Verify the final 1-8 checksum bits
            if (checksumBits != seedChecksumBits)
            {
                // Clear arrays and throw exception
                Array.Clear(entropyBytes, 0, entropyBytes.Length);
                Array.Clear(seedChecksumBytes, 0, seedChecksumBytes.Length);
                Array.Clear(checksumBytes, 0, checksumBytes.Length);
                throw new ArgumentException("Checksum doesn't match.");
            }
            // Clear checksum arrays if checksum is valid
            Array.Clear(seedChecksumBytes, 0, seedChecksumBytes.Length);
            Array.Clear(checksumBytes, 0, checksumBytes.Length);

            return entropyBytes;
        }

        /// <summary>
        /// Convert BIP-0039 mnemonic seed words and a passphrase to a BIP-0039 binary seed.
        /// </summary>
        /// <param name="seedWords">An array of BIP-0039 mnemonic words.</param>
        /// <param name="passphrase">The BIP-0039 passphrase used in PBKDF2. Use <see cref="string.Empty"/> if no passphrase.</param>
        /// <returns>The binary representation of a BIP-0039 binary seed.</returns>
        public static byte[] GetBinarySeedFromSeedWords(ref string[] seedWords, SecureString? passphrase)
        {
            // Password for PBKDF2
            byte[] passwordBytes = Encoding.UTF8.GetBytes(string.Join(' ', seedWords).Normalize(NormalizationForm.FormKD));
            // Salt for PBKDF2
            char[] mnemonicString = "mnemonic".ToCharArray();
            char[] saltChars = new char[mnemonicString.Length + (passphrase is not null ? passphrase.Length : 0)];
            Array.Copy(mnemonicString, 0, saltChars, 0, mnemonicString.Length);

            if (passphrase?.Length > 0)
            {
                int maxBytes = Encoding.UTF8.GetMaxByteCount(passphrase.Length);
                IntPtr bytes = IntPtr.Zero;
                IntPtr str = IntPtr.Zero;

                try
                {
                    bytes = Marshal.AllocHGlobal(maxBytes);
                    str = Marshal.SecureStringToBSTR(passphrase);

                    unsafe
                    {
                        char* chars = (char*)str.ToPointer();
                        byte* bytesPtr = (byte*)bytes.ToPointer();
                        int len = Encoding.UTF8.GetBytes(chars, passphrase.Length, bytesPtr, maxBytes);

                        byte[] _bytes = new byte[len];
                        for (int i = 0; i < len; ++i)
                        {
                            _bytes[i] = *bytesPtr;
                            bytesPtr++;
                        }
                        char[] passphraseChars = Encoding.UTF8.GetChars(_bytes);
                        Array.Copy(passphraseChars, 0, saltChars, mnemonicString.Length, passphraseChars.Length);
                        Array.Clear(passphraseChars, 0, passphraseChars.Length);
                        Array.Clear(_bytes, 0, _bytes.Length);
                    }
                }
                finally
                {
                    if (bytes != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(bytes);
                    }
                    if (str != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(str);
                    }
                }
            }
            byte[] salt = Encoding.UTF8.GetBytes(saltChars);//.Normalize(NormalizationForm.FormKD));
            Array.Clear(saltChars, 0, saltChars.Length);
            // Initialise a PBKDF2 instance
            using Rfc2898DeriveBytes pbkdf2Instance = new(passwordBytes, salt, 2048, HashAlgorithmName.SHA512);
            // Clear arrays
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
            Array.Clear(salt, 0, salt.Length);
            // Return the first 64 bytes from PBKDF2 (the binary seed)
            return pbkdf2Instance.GetBytes(64);
        }
    }
}
