using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
    [TestClass]
    public class Z85Tests
    {
        public static async Task<List<Models.Z85TestVector>?> GetTestVectorsAsync()
        {
            using FileStream openStream = File.OpenRead(@"contrib/zeromq/z85-vectors.json");
            Models.Z85TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Z85TestVectorsRoot>(openStream);
            openStream.Close();
            return jsonRoot?.TestVectors;
        }

        [TestMethod]
        public async Task TryGetEncodedBytesTest()
        {
            IEnumerable<Models.Z85TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                byte[] unencoded = Convert.FromHexString(testVector.DecodedHex);
                Assert.IsTrue(Z85.TryGetEncodedBytes(unencoded, out byte[]? encoded));
                Assert.IsNotNull(encoded);
                Assert.AreEqual(testVector.EncodedBytes, Encoding.UTF8.GetString(encoded));
            });
        }

        [TestMethod]
        public async Task TryGetDecodedBytesTest()
        {
            IEnumerable<Models.Z85TestVector>? testVectors = await GetTestVectorsAsync();
            Assert.IsNotNull(testVectors);
            _ = Parallel.ForEach(testVectors, testVector =>
            {
                byte[] encoded = Encoding.UTF8.GetBytes(testVector.EncodedBytes);
                Assert.IsTrue(Z85.TryGetDecodedBytes(encoded, out byte[]? decoded));
                Assert.IsNotNull(decoded);
                string decodedHex = Convert.ToHexString(decoded).ToLowerInvariant();
                Assert.AreEqual(testVector.DecodedHex, decodedHex);
            });
        }
    }
}
