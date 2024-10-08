﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
    [TestClass]
    public class Slip21Tests
    {
        public static async Task<List<Models.Slip21TestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/slip0021-vectors.json");
            Models.Slip21TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Slip21TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot?.English;
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<Models.Slip21TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                byte[] binarySeed = Bip39.GetBinarySeedFromSeedWords(ref mnemonic, null);
                string binarySeedHex = Convert.ToHexString(binarySeed).ToLowerInvariant();
                Assert.AreEqual(testVector.MnemonicBinarySeed, binarySeedHex);
            });
        }

        [TestMethod]
        public async Task DeriveMasterNodeTest()
        {
            IEnumerable<Models.Slip21TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), "0");
                string masterNodePrivateKey = Convert.ToHexString(masterNode.Right).ToLowerInvariant();
                Assert.AreEqual(testVector.MasterNodeKey, masterNodePrivateKey);
            });
        }

        [TestMethod]
        public async Task GetChildNodeTest()
        {
            IEnumerable<Models.Slip21TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), "0");
                Slip21Node childNode = masterNode.GetChildNode("SLIP-0021");
                string slip21NodePrivateKey = Convert.ToHexString(childNode.Right).ToLowerInvariant();
                Assert.AreEqual(testVector.Slip21NodeKey, slip21NodePrivateKey);
            });
        }

        [TestMethod]
        public async Task GetGrandchildNode1Test()
        {
            IEnumerable<Models.Slip21TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), "0");
                Slip21Node grandchildNode = masterNode.GetChildNode("SLIP-0021").GetChildNode("Master encryption key");
                string masterEncryptionKey = Convert.ToHexString(grandchildNode.Right).ToLowerInvariant();
                Assert.AreEqual(testVector.Slip21NodeMasterEncryptionKey, masterEncryptionKey);
            });
        }

        [TestMethod]
        public async Task GetGrandchildNode2Test()
        {
            IEnumerable<Models.Slip21TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), "0");
                Slip21Node grandchildNode = masterNode.GetChildNode("SLIP-0021").GetChildNode("Authentication key");
                string authenticationKey = Convert.ToHexString(grandchildNode.Right).ToLowerInvariant();
                Assert.AreEqual(testVector.Slip21NodeAuthenticationKey, authenticationKey);
            });
        }
    }
}
