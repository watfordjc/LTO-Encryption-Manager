using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Base58TestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public Collection<Base58TestVector>? Vectors { get; init; }
	}

	public class Base58TestVector : Collection<string>
	{
		public string InputEncoding => this[0];
		public string InputDecoded => InputEncoding == "HEX" ? this[1].ToUpperInvariant() : this[1];
		public string OutputEncoded => this[2];
	}
}
