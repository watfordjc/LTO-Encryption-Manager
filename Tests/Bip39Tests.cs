using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
	[TestClass]
    public class Bip39Tests
    {
        public static async Task<Collection<Models.Bip39TestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"contrib/trezor/python-mnemonic/vectors.json");
            Models.Bip39TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip39TestVectorsRoot>(openStream).ConfigureAwait(false);
            openStream.Close();
            return jsonRoot?.English;
        }

        [TestMethod]
        public async Task GetMnemonicStringFromEntropyTest()
        {
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string mnemonicString = Bip39.GetMnemonicFromEntropy(testVector.Entropy);
                Assert.AreEqual(testVector.MnemonicSeed, mnemonicString);
            });
        }

        [TestMethod]
        public async Task GetEntropyBytesFromSeedWordsTest()
        {
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
              {
                  string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                  byte[] entropyBytes = Bip39.GetEntropyBytesFromSeedWords(ref mnemonic);
                  string entropyHex = Convert.ToHexString(entropyBytes).ToUpperInvariant();
                  Assert.AreEqual(testVector.Entropy, entropyHex);
              });
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                SecureString testPassphrase = new();
                foreach (char c in "TREZOR")
                {
                    testPassphrase.AppendChar(c);
                }
                testPassphrase.MakeReadOnly();
                byte[] binarySeed = Bip39.GetBinarySeedFromSeedWords(ref mnemonic, testPassphrase);
                string binarySeedHex = Convert.ToHexString(binarySeed).ToUpperInvariant();
                Assert.AreEqual(testVector.MnemonicBinarySeed, binarySeedHex);
            });
        }
    }
}
