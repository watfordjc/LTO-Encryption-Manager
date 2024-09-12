using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Bip85DrngEntropyTestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public Collection<Bip85DrngEntropyTestVector>? Vectors { get; init; }
	}

	public class Bip85DrngEntropyTestVector : Collection<string>
	{
		[JsonIgnore]
		public string MasterNodePrivateKey => this[0];
		[JsonIgnore]
		public string DerivationPath => this[1];
		[JsonIgnore]
		public string PrivateKeyHex => this[2].ToUpperInvariant();
		[JsonIgnore]
		public string EntropyHex  => this[3].ToUpperInvariant();
		[JsonIgnore]
		public int RequestedEntropyBytes => int.Parse(this[4], NumberStyles.None, CultureInfo.InvariantCulture);
		[JsonIgnore]
		public string DrngEntropyHex => this[5].ToUpperInvariant();
		[JsonIgnore]
		public string DrngEntropy80BSha512Hash => this[6].ToUpperInvariant();
		[JsonIgnore]
		public string DrngEntropy1KiBSha512Hash => this[7].ToUpperInvariant();
		[JsonIgnore]
		public string DrngEntropy1MiBSha512Hash => this[8].ToUpperInvariant();
		[JsonIgnore]
		public string DrngEntropy5MiBSha512Hash => this[9].ToUpperInvariant();
		[JsonIgnore]
		public string DrngEntropy1GiBSha512Hash => this[10].ToUpperInvariant();
	}
}
