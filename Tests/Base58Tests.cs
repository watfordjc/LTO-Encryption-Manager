using CryptHash.Net.Encoding;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
	[TestClass]
	public class Base58Tests
	{
		public static async Task<Collection<Models.Base58TestVector>?> GetTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/base58-vectors.json");
			Models.Base58TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Base58TestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.Vectors;
		}

		[TestMethod]
		public async Task Base58Encode()
		{
			IEnumerable<Models.Base58TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				byte[]? input = testVector.InputEncoding switch
				{
					"UTF-8" => Encoding.UTF8.GetBytes(testVector.InputDecoded),
					"HEX" => testVector.InputDecoded.Length > 0 ? Hexadecimal.ToByteArray(testVector.InputDecoded) : [],
					_ => null
				};
				Assert.IsNotNull(input);
				bool success = Base58.TryGetRawBase58FromBase256(input, out byte[]? outputRaw);
				Assert.IsTrue(success);
				string output = Base58.TryGetBase58StringFromRawBase58(outputRaw);
				Assert.AreEqual(testVector.OutputEncoded, output, false, CultureInfo.InvariantCulture);
			});
		}

		[TestMethod]
		public async Task Base58Decode()
		{
			IEnumerable<Models.Base58TestVector>? testVectors = await GetTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				byte[] inputRaw = Base58.GetBase256FromBase58String(Encoding.UTF8.GetBytes(testVector.OutputEncoded));
				string? input = testVector.InputEncoding switch
				{
					"UTF-8" => Encoding.UTF8.GetString(inputRaw),
					"HEX" => testVector.InputDecoded.Length > 0 ? Hexadecimal.ToHexString(inputRaw).ToUpperInvariant() : string.Empty,
					_ => null
				};
				Assert.IsNotNull(input);
				Assert.AreEqual(testVector.InputDecoded, input, false, CultureInfo.InvariantCulture);
			});
		}
	}
}
