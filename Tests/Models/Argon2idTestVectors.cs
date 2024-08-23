using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json.Serialization;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Argon2idTestVectorsRoot
    {
        [JsonPropertyName("testVectors")]
        public Collection<Argon2idTestVector>? TestVectors { get; init; }
    }

    public class Argon2idTestVector : Collection<string>
    {
        [JsonIgnore]
        public int MemoryKibiBytes => int.Parse(this[0], NumberStyles.None, CultureInfo.InvariantCulture);
        [JsonIgnore]
        public int Iterations => int.Parse(this[1], NumberStyles.None, CultureInfo.InvariantCulture);
        [JsonIgnore]
        public int Parallelism => int.Parse(this[2], NumberStyles.None, CultureInfo.InvariantCulture);
        [JsonIgnore]
        public int OutputLength => int.Parse(this[3], NumberStyles.None, CultureInfo.InvariantCulture);
        [JsonIgnore]
        public string Message => this[4];
        [JsonIgnore]
        public string Salt => this[5];
        [JsonIgnore]
        public string Secret => this[6];
        [JsonIgnore]
        public string AssociatedData => this[7];
        [JsonIgnore]
        public string Output => this[8].ToUpperInvariant();
    }
}
