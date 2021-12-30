using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests.model
{
    public class Z85TestVectorsRoot
    {
        [JsonPropertyName("testVectors")]
        public List<Z85TestVector> TestVectors { get; set; }
    }

    public class Z85TestVector : List<string>
    {
        [JsonIgnore]
        public string DecodedHex => this[0];
        [JsonIgnore]
        public string EncodedBytes => this[1];
    }
}
