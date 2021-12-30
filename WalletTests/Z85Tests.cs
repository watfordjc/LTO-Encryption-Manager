using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Wallet;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests
{
    [TestClass]
    public class Z85Tests
    {
        public static async Task<List<model.Z85TestVector>> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"data/z85-vectors.json");
            model.Z85TestVectorsRoot jsonRoot = await JsonSerializer.DeserializeAsync<model.Z85TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot.TestVectors;
        }

        [TestMethod]
        public async Task TryGetEncodedBytesTest()
        {
            IEnumerable<model.Z85TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                byte[] unencoded = Convert.FromHexString(testVector.DecodedHex);
                Assert.IsTrue(Z85.TryGetEncodedBytes(unencoded, out byte[] encoded));
                Assert.AreEqual(testVector.EncodedBytes, Encoding.UTF8.GetString(encoded));
            });
        }

        [TestMethod]
        public async Task TryGetDecodedBytesTest()
        {
            IEnumerable<model.Z85TestVector> testVectors = await GetTestVectorsAsync();
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                byte[] encoded = Encoding.UTF8.GetBytes(testVector.EncodedBytes);
                Assert.IsTrue(Z85.TryGetDecodedBytes(encoded, out byte[] decoded));
                string decodedHex = Convert.ToHexString(decoded).ToLowerInvariant();
                Assert.AreEqual(testVector.DecodedHex, decodedHex);
            });
        }
    }
}
