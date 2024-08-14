using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Base58TestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public List<Base58TestVector>? Vectors { get; set; }
	}

	public class Base58TestVector : List<string>
	{
		public string InputEncoding => this[0];
		public string InputDecoded => this[1];
		public string OutputEncoded => this[2];
	}
}
