using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.AlgorithmTests
{
    [TestClass]
    public class Argon2idTests
    {
        public static async Task<Collection<Models.Argon2idTestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/argon2id-vectors.json");
            Models.Argon2idTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Argon2idTestVectorsRoot>(openStream).ConfigureAwait(false);
            openStream.Close();
            return jsonRoot?.TestVectors;
        }

        [TestMethod]
        public async Task GetHashTest()
        {
            IEnumerable<Models.Argon2idTestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
            Assert.IsNotNull(testVectors);
            using SemaphoreSlim semaphore = new(1);
            Argon2id argon2id = new();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                semaphore.Wait();
                Argon2idHashResult hashResult = Utils.Algorithms.Argon2id.GetHash(
                    argon2id: argon2id,
                    message: Utils.ByteEncoding.FromHexString(testVector.Message),
                    salt: Utils.ByteEncoding.FromHexString(testVector.Salt),
                    iterations: testVector.Iterations,
                    memKibiBytes: testVector.MemoryKibiBytes,
                    parallelism: testVector.Parallelism,
                    outputLength: testVector.OutputLength,
                    associatedData: Utils.ByteEncoding.FromHexString(testVector.AssociatedData),
                    knownSecret: Utils.ByteEncoding.FromHexString(testVector.Secret));
                Assert.AreEqual(testVector.Output, Utils.ByteEncoding.ToHexString(hashResult.HashBytes));
                semaphore.Release();
            });
        }
    }
}
