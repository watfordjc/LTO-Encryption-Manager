using System;
using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class RsaTestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public Collection<RsaTestVector>? Vectors { get; init; }
	}

	public class RsaTestVector: Collection<string>
	{
		[JsonIgnore]
		public ReadOnlySpan<byte> Modulus => ByteEncoding.FromHexString(this[0]);
		[JsonIgnore]
		public ReadOnlySpan<byte> PublicExponent => ByteEncoding.FromHexString(this[1]);
		[JsonIgnore]
		public ReadOnlySpan<byte> PrivateExponent => ByteEncoding.FromHexString(this[2]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Prime1 => ByteEncoding.FromHexString(this[3]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Prime2 => ByteEncoding.FromHexString(this[4]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Exponent1 => ByteEncoding.FromHexString(this[5]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Exponent2 => ByteEncoding.FromHexString(this[6]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Coefficient => ByteEncoding.FromHexString(this[7]);
		[JsonIgnore]
		public ReadOnlySpan<byte> PemSha256Hash => ByteEncoding.FromHexString(this[8]);
		[JsonIgnore]
		public string PemSha256HashString => ByteEncoding.ToHexString(PemSha256Hash);
		[JsonIgnore]
		public string MasterNodePrivateKey => this[9];
		[JsonIgnore]
		public string DerivationPath => this[10];
		[JsonIgnore]
		public string EntropyHex => this[11].ToUpperInvariant();
		[JsonIgnore]
		public ReadOnlySpan<byte> Shake256Output1 => ByteEncoding.FromHexString(this[12]);
		[JsonIgnore]
		public ReadOnlySpan<byte> Shake256Output2 => ByteEncoding.FromHexString(this[13]);
	}
}
