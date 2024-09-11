using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.SLIPTests
{
    [TestClass]
    public class Slip21LtoAesTests
    {
        public static async Task<Collection<Models.Slip21LtoAesTestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/slip0021-lto-aes-vectors.json");
            Models.Slip21LtoAesTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Slip21LtoAesTestVectorsRoot>(openStream).ConfigureAwait(false);
            openStream.Close();
            return jsonRoot?.English;
        }

        [TestMethod]
        public async Task GetBinarySeedFromSeedWordsTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                string[] mnemonic = testVector.MnemonicSeed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                byte[] binarySeed = Bip39.GetBinarySeedFromSeedWords(ref mnemonic, null);
                string binarySeedHex = Utils.ByteEncoding.ToHexString(binarySeed);
                Assert.AreEqual(testVector.MnemonicBinarySeed, binarySeedHex);
            });
        }

        [TestMethod]
        public async Task DeriveMasterNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Utils.ByteEncoding.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                string masterNodePrivateKey = Utils.ByteEncoding.ToHexString(masterNode.Right);
                Assert.AreEqual(testVector.MasterNodeKey, masterNodePrivateKey);
            });
        }

        [TestMethod]
        public async Task FingerprintGlobalNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            using SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Utils.ByteEncoding.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node globalNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount);
                Slip21ValidationNode validationNode = new(globalNode);
                validationNode.FingerprintingCompleted += (object? sender, FingerprintingCompletedEventArgs e) =>
                {
                    semaphore.Release();
                    Assert.IsTrue(e.HasCompleted);
                    Assert.AreEqual(testVector.MasterNodeFingerprint, validationNode.Fingerprint);
                };
                // Given the memory usage of Argon2id, only allow one thread to calculate a fingerprint at a time
                semaphore.Wait();
                validationNode.CalculateFingerprint();
            });
            await semaphore.WaitAsync().ConfigureAwait(false);
            semaphore.Dispose();
        }

        [TestMethod]
        public async Task FingerprintAccountNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            using SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Utils.ByteEncoding.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node accountNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount).GetChildNode(testVector.AccountId).GetChildNode(testVector.AccountKeyRolloverCount);
                Slip21ValidationNode validationNode = new(accountNode);
                validationNode.FingerprintingCompleted += (object? sender, FingerprintingCompletedEventArgs e) =>
                {
                    semaphore.Release();
                    Assert.IsTrue(e.HasCompleted);
                    Assert.AreEqual(testVector.AccountNodeFingerprint, validationNode.Fingerprint);
                };
                // Given the memory usage of Argon2id, only allow one thread to calculate a fingerprint at a time
                semaphore.Wait();
                validationNode.CalculateFingerprint();
            });
            await semaphore.WaitAsync().ConfigureAwait(false);
            semaphore.Dispose();
        }

        [TestMethod]
        public async Task FingerprintTapeNodeTest()
        {
            IEnumerable<Models.Slip21LtoAesTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            using SemaphoreSlim semaphore = new(1);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(Utils.ByteEncoding.FromHexString(testVector.MnemonicBinarySeed), testVector.GlobalKeyRolloverCount);
                Slip21Node tapeNode = masterNode.GetChildNode(testVector.Slip0021Schema).GetChildNode(testVector.GlobalKeyRolloverCount).GetChildNode(testVector.AccountId).GetChildNode(testVector.AccountKeyRolloverCount).GetChildNode(testVector.TapeLabel).GetChildNode(testVector.TapeKeyRolloverCount);
                Slip21ValidationNode validationNode = new(tapeNode);
                validationNode.FingerprintingCompleted += (object? sender, FingerprintingCompletedEventArgs e) =>
                {
                    semaphore.Release();
                    Assert.IsTrue(e.HasCompleted);
                    Assert.AreEqual(testVector.TapeNodeFingerprint, validationNode.Fingerprint);
                };
                // Given the memory usage of Argon2id, only allow one thread to calculate a fingerprint at a time
                semaphore.Wait();
                validationNode.CalculateFingerprint();
            });
            await semaphore.WaitAsync().ConfigureAwait(false);
            semaphore.Dispose();
        }
    }
}
