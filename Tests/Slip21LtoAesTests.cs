using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
    [TestClass]
    public class Slip21LtoAesTests
    {
        public static async Task<List<Models.Slip21LtoAesTestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/slip0021-lto-aes-vectors.json");
            Models.Slip21LtoAesTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Slip21LtoAesTestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot?.English;
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync();
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
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                string masterNodePrivateKey = Convert.ToHexString(masterNode.Right).ToLowerInvariant();
                Assert.AreEqual(testVector.MasterNodeKey, masterNodePrivateKey);
            });
        }

        [TestMethod]
        public async Task FingerprintGlobalNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                semaphore.Wait();
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node globalNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount);
                Slip21ValidationNode validationNode = new(globalNode);
                validationNode.FingerprintingCompleted += (object? sender, bool e) =>
                {
                    Assert.AreEqual(testVector.MasterNodeFingerprint, validationNode.Fingerprint);
                    semaphore.Release();
                };
                validationNode.CalculateFingerprint();
            });
            semaphore.Wait();
            semaphore.Dispose();
        }

        [TestMethod]
        public async Task FingerprintAccountNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                semaphore.Wait();
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node accountNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount).GetChildNode(testVector.AccountId).GetChildNode(testVector.AccountKeyRolloverCount);
                Slip21ValidationNode validationNode = new(accountNode);
                validationNode.FingerprintingCompleted += (object? sender, bool e) =>
                {
                    Assert.AreEqual(testVector.AccountNodeFingerprint, validationNode.Fingerprint);
                    semaphore.Release();
                };
                validationNode.CalculateFingerprint();
            });
            semaphore.Wait();
            semaphore.Release();
        }

        [TestMethod]
        public async Task FingerprintTapeNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                semaphore.Wait();
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Convert.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node tapeNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount).GetChildNode(testVector.AccountId).GetChildNode(testVector.AccountKeyRolloverCount).GetChildNode(testVector.TapeLabel).GetChildNode(testVector.TapeKeyRolloverCount);
                Slip21ValidationNode validationNode = new(tapeNode);
                validationNode.FingerprintingCompleted += (object? sender, bool e) =>
                {
                    Assert.AreEqual(testVector.TapeNodeFingerprint, validationNode.Fingerprint);
                    semaphore.Release();
                };
                validationNode.CalculateFingerprint();
            });
            semaphore.Wait();
            semaphore.Release();
        }
    }
}
