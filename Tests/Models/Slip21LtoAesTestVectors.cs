using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Slip21LtoAesTestVectorsRoot
    {
        [JsonPropertyName("english")]
        public Collection<Slip21LtoAesTestVector>? English { get; init; }
    }

    public class Slip21LtoAesTestVector : Collection<string>
    {
        [JsonIgnore]
        public string MnemonicSeed => this[0];
        [JsonIgnore]
        public string MnemonicBinarySeed => this[1].ToUpperInvariant();
        [JsonIgnore]
        public string Slip0021Schema => this[2];
        [JsonIgnore]
        public string GlobalKeyRolloverCount => this[3];
        [JsonIgnore]
        public string AccountId => this[4];
        [JsonIgnore]
        public string AccountKeyRolloverCount => this[5];
        [JsonIgnore]
        public string TapeLabel => this[6];
        [JsonIgnore]
        public string TapeKeyRolloverCount => this[7];
        [JsonIgnore]
        public string MasterNodeKey => this[8].ToUpperInvariant();
        [JsonIgnore]
        public string MasterNodeFingerprint => this[9];
        [JsonIgnore]
        public string AccountNodeFingerprint => this[10];
        [JsonIgnore]
        public string TapeNodeFingerprint => this[11];
    }
}
