using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
    [TestClass]
    public class Bip39Tests
    {
        public static async Task<List<Models.Bip39TestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"contrib/trezor/python-mnemonic/vectors.json");
            Models.Bip39TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip39TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot?.English;
        }

        [TestMethod]
        public async Task GetMnemonicStringFromEntropyTest()
        {
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync();
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
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
              {
                  string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                  byte[] entropyBytes = Bip39.GetEntropyBytesFromSeedWords(ref mnemonic);
                  string entropyHex = Convert.ToHexString(entropyBytes).ToLowerInvariant();
                  Assert.AreEqual(testVector.Entropy, entropyHex);
              });
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<Models.Bip39TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                byte[] binarySeed = Bip39.GetBinarySeedFromSeedWords(ref mnemonic, "TREZOR");
                string binarySeedHex = Convert.ToHexString(binarySeed).ToLowerInvariant();
                Assert.AreEqual(testVector.MnemonicBinarySeed, binarySeedHex);
            });
        }
    }
}
