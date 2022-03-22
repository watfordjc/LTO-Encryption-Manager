using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
    [TestClass]
    public class Argon2idTests
    {
        public static async Task<List<Models.Argon2idTestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/argon2id-vectors.json");
            Models.Argon2idTestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Argon2idTestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot?.TestVectors;
        }

        [TestMethod]
        public async Task GetHashTest()
        {
            IEnumerable<Models.Argon2idTestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            SemaphoreSlim semaphore = new(1);
            Argon2id argon2id = new();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                semaphore.Wait();
                Argon2idHashResult hashResult = Utils.Algorithms.Argon2id.GetHash(
                    argon2id: argon2id,
                    message: Convert.FromHexString(testVector.Message),
                    salt: Convert.FromHexString(testVector.Salt),
                    iterations: testVector.Iterations,
                    memKibiBytes: testVector.MemoryKibiBytes,
                    parallelism: testVector.Parallelism,
                    outputLength: testVector.OutputLength,
                    associatedData: Convert.FromHexString(testVector.AssociatedData),
                    knownSecret: Convert.FromHexString(testVector.Secret));
                Assert.AreEqual(testVector.Output, Convert.ToHexString(hashResult.HashBytes).ToLowerInvariant());
                semaphore.Release();
            });
        }
    }
}
