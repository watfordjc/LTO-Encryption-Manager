using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Z85TestVectorsRoot
    {
        [JsonPropertyName("testVectors")]
        public Collection<Z85TestVector>? TestVectors { get; init; }
    }

    public class Z85TestVector : Collection<string>
    {
        [JsonIgnore]
        public string DecodedHex => this[0].ToUpperInvariant();
        [JsonIgnore]
        public string EncodedBytes => this[1];
    }
}
