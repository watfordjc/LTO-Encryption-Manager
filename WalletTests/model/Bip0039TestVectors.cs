using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests.model
{
    public class Bip0039TestVectorsRoot
    {
        [JsonPropertyName("english")]
        public List<Bip0039TestVector> English { get; set; }
    }

    public class Bip0039TestVector : List<string>
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
