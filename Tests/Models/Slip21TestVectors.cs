using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Slip21TestVectorsRoot
    {
        [JsonPropertyName("english")]
        public Collection<Slip21TestVector>? English { get; init; }
    }

    public class Slip21TestVector : Collection<string>
    {
        [JsonIgnore]
        public string MnemonicSeed => this[0];
        [JsonIgnore]
        public string MnemonicBinarySeed => this[1].ToUpperInvariant();
        [JsonIgnore]
        public string MasterNodeKey => this[2].ToUpperInvariant();
        [JsonIgnore]
        public string Slip21NodeKey => this[3].ToUpperInvariant();
        [JsonIgnore]
        public string Slip21NodeMasterEncryptionKey => this[4].ToUpperInvariant();
        [JsonIgnore]
        public string Slip21NodeAuthenticationKey => this[5].ToUpperInvariant();
    }
}
