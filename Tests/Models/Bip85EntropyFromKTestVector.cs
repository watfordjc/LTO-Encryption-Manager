using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Bip85EntropyFromKTestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public Collection<Bip85EntropyFromKTestVector>? Vectors { get; init; }
	}

	public class Bip85EntropyFromKTestVector : Collection<string>
	{
		public string MasterNodePrivateKey => this[0];
		public string DerivationPath => this[1];
		public string PrivateKeyHex => this[2].ToUpperInvariant();
		public string EntropyHex  => this[3].ToUpperInvariant();
	}
}
