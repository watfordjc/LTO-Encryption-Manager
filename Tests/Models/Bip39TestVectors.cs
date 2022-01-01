using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
    public class Bip39TestVectorsRoot
    {
        [JsonPropertyName("english")]
        public List<Bip39TestVector> English { get; set; }
    }

    public class Bip39TestVector : List<string>
    {
        [JsonIgnore]
        public string Entropy => this[0];
        [JsonIgnore]
        public string MnemonicSeed => this[1];
        [JsonIgnore]
        public string MnemonicBinarySeed => this[2];
        [JsonIgnore]
        public string PrivateKey => this[3];
    }
}
