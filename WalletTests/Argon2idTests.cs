using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests
{
    [TestClass]
    public class Argon2idTests
    {
        public static async Task<List<model.Argon2idTestVector>> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/argon2id-vectors.json");
            model.Argon2idTestVectorsRoot jsonRoot = await JsonSerializer.DeserializeAsync<model.Argon2idTestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot.TestVectors;
        }

        [TestMethod]
        public async Task GetHashTest()
        {
            IEnumerable<model.Argon2idTestVector> testVectors = await GetTestVectorsAsync();
            Argon2id argon2id = new();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                Argon2idHashResult hashResult = Wallet.Argon2id.GetHash(
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
            });
        }
    }
}
