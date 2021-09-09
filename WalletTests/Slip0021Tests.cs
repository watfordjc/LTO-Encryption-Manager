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
    public class Slip0021Tests
    {
        public static async Task<List<model.Slip0021TestVector>> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/slip0021-vectors.json");
            model.Slip0021TestVectorsRoot jsonRoot = await JsonSerializer.DeserializeAsync<model.Slip0021TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot.English;
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<model.Slip0021TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                byte[] binarySeed = Bip0039.GetBinarySeedFromSeedWords(ref mnemonic, string.Empty);
                string binarySeedHex = Convert.ToHexString(binarySeed).ToLowerInvariant();
                Assert.AreEqual(binarySeedHex, testVector.MnemonicBinarySeed);
            });
        }

        [TestMethod]
        public async Task DeriveMasterNodeTest()
        {
            IEnumerable<model.Slip0021TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip0021Node masterNode = Slip0021.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed));
                string masterNodePrivateKey = Convert.ToHexString(masterNode.Right).ToLowerInvariant();
                Assert.AreEqual(masterNodePrivateKey, testVector.MasterNodeKey);
            });
        }

        [TestMethod]
        public async Task GetChildNodeTest()
        {
            IEnumerable<model.Slip0021TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip0021Node masterNode = Slip0021.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed));
                Slip0021Node childNode = masterNode.GetChildNode("SLIP-0021");
                string slip21NodePrivateKey = Convert.ToHexString(childNode.Right).ToLowerInvariant();
                Assert.AreEqual(slip21NodePrivateKey, testVector.Slip21NodeKey);
            });
        }

        [TestMethod]
        public async Task GetGrandchildNode1Test()
        {
            IEnumerable<model.Slip0021TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip0021Node masterNode = Slip0021.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed));
                Slip0021Node grandchildNode = masterNode.GetChildNode("SLIP-0021").GetChildNode("Master encryption key");
                string masterEncryptionKey = Convert.ToHexString(grandchildNode.Right).ToLowerInvariant();
                Assert.AreEqual(masterEncryptionKey, testVector.Slip21NodeMasterEncryptionKey);
            });
        }

        [TestMethod]
        public async Task GetGrandchildNode2Test()
        {
            IEnumerable<model.Slip0021TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip0021Node masterNode = Slip0021.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed));
                Slip0021Node grandchildNode = masterNode.GetChildNode("SLIP-0021").GetChildNode("Authentication key");
                string authenticationKey = Convert.ToHexString(grandchildNode.Right).ToLowerInvariant();
                Assert.AreEqual(authenticationKey, testVector.Slip21NodeAuthenticationKey);
            });
        }
    }
}
