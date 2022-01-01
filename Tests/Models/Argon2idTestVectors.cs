using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
    public class Argon2idTestVectorsRoot
    {
        [JsonPropertyName("testVectors")]
        public List<Argon2idTestVector> TestVectors { get; set; }
    }

    public class Argon2idTestVector : List<string>
    {
        [JsonIgnore]
        public int MemoryKibiBytes => int.Parse(this[0]);
        [JsonIgnore]
        public int Iterations => int.Parse(this[1]);
        [JsonIgnore]
        public int Parallelism => int.Parse(this[2]);
        [JsonIgnore]
        public int OutputLength => int.Parse(this[3]);
        [JsonIgnore]
        public string Message => this[4];
        [JsonIgnore]
        public string Salt => this[5];
        [JsonIgnore]
        public string Secret => this[6];
        [JsonIgnore]
        public string AssociatedData => this[7];
        [JsonIgnore]
        public string Output => this[8];
    }
}
