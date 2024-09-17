using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.ByteEncodingTests
{
	[TestClass]
	public class Z85Tests
	{
		public static async Task<Collection<Models.Z85TestVector>?> GetTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"contrib/zeromq/z85-vectors.json");
			Models.Z85TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Z85TestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.TestVectors;
		}

		[TestMethod]
		public async Task TryGetEncodedBytesTest()
		{
			IEnumerable<Models.Z85TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				byte[] unencoded = Utils.ByteEncoding.FromHexString(testVector.DecodedHex);
				Assert.IsTrue(Utils.ByteEncoding.TryGetToZ85Encoded(unencoded, out char[]? encoded));
				Assert.IsNotNull(encoded);
				Assert.AreEqual(testVector.EncodedBytes, new string(encoded));
			});
		}

		[TestMethod]
		public async Task TryGetDecodedBytesTest()
		{
			IEnumerable<Models.Z85TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				char[] encoded = testVector.EncodedBytes.ToCharArray();
				Assert.IsTrue(Utils.ByteEncoding.TryGetFromZ85Encoded(encoded.AsSpan(), out byte[]? decoded));
				Assert.IsNotNull(decoded);
				string decodedHex = Utils.ByteEncoding.ToHexString(decoded);
				Assert.AreEqual(testVector.DecodedHex, decodedHex);
			});
		}
	}
}
