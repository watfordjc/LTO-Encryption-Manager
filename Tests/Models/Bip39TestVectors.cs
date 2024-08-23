using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Bip39TestVectorsRoot
    {
        [JsonPropertyName("english")]
        public Collection<Bip39TestVector>? English { get; init; }
    }

    public class Bip39TestVector : Collection<string>
    {
        [JsonIgnore]
        public string Entropy => this[0].ToUpperInvariant();
        [JsonIgnore]
        public string MnemonicSeed => this[1];
        [JsonIgnore]
        public string MnemonicBinarySeed => this[2].ToUpperInvariant();
        [JsonIgnore]
        public string PrivateKey => this[3];
    }
}
