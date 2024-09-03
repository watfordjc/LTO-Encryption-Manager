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
		public string MasterNodePrivateKey => this[0];
		public string DerivationPath => this[1];
		public string PrivateKeyHex => this[2].ToUpperInvariant();
		public string EntropyHex  => this[3].ToUpperInvariant();
		public int RequestedEntropyBytes => int.Parse(this[4], NumberStyles.None, CultureInfo.InvariantCulture);
		public string DrngEntropyHex => this[5].ToUpperInvariant();
	}
}
