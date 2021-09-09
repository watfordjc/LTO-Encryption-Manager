using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.WalletTests.model
{
    public class Slip0021TestVectorsRoot
    {
        [JsonPropertyName("english")]
        public List<Slip0021TestVector> English { get; set; }
    }

    public class Slip0021TestVector : List<string>
    {
        [JsonIgnore]
        public string MnemonicSeed => this[0];
        [JsonIgnore]
        public string MnemonicBinarySeed => this[1];
        [JsonIgnore]
        public string MasterNodeKey => this[2];
        [JsonIgnore]
        public string Slip21NodeKey => this[3];
        [JsonIgnore]
        public string Slip21NodeMasterEncryptionKey => this[4];
        [JsonIgnore]
        public string Slip21NodeAuthenticationKey => this[5];
    }
}
