using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Wallet;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests
{
    [TestClass]
    public class Bip0039Tests
    {
        public static async Task<List<model.Bip0039TestVector>> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"contrib/trezor/python-mnemonic/vectors.json");
            model.Bip0039TestVectorsRoot jsonRoot = await JsonSerializer.DeserializeAsync<model.Bip0039TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot.English;
        }

        [TestMethod]
        public async Task GetMnemonicStringFromEntropyTest()
        {
            IEnumerable<model.Bip0039TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string mnemonicString = Bip0039.GetMnemonicFromEntropy(testVector.Entropy);
                Assert.AreEqual(testVector.MnemonicSeed, mnemonicString);
            });
        }

        [TestMethod]
        public async Task GetEntropyBytesFromSeedWordsTest()
        {
            IEnumerable<model.Bip0039TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
              {
                  string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                  byte[] entropyBytes = Bip0039.GetEntropyBytesFromSeedWords(ref mnemonic);
                  string entropyHex = Convert.ToHexString(entropyBytes).ToLowerInvariant();
                  Assert.AreEqual(testVector.Entropy, entropyHex);
              });
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<model.Bip0039TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                byte[] binarySeed = Bip0039.GetBinarySeedFromSeedWords(ref mnemonic, "TREZOR");
                string binarySeedHex = Convert.ToHexString(binarySeed).ToLowerInvariant();
                Assert.AreEqual(testVector.MnemonicBinarySeed, binarySeedHex);
            });
        }
    }
}
