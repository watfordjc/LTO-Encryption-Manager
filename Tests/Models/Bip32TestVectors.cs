using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.Models
{
	public class Bip32TestVectorsRoot
	{
		[JsonPropertyName("vectors")]
		public List<Bip32TestVector>? Vectors { get; set; }
	}

	public class Bip32TestVector : List<string>
	{
		public string CurveName => this[0];
		public string PublicKeyPrefix => this[1];
		public uint? PublicKeyPrefixValue => BitConverter.ToUInt32(Bip32.ReversePrefixBytes(Convert.FromHexString(PublicKeyPrefix)));
		public string PrivateKeyPrefix => this[2];
		public uint? PrivateKeyPrefixValue => BitConverter.ToUInt32(Bip32.ReversePrefixBytes(Convert.FromHexString(PrivateKeyPrefix)));
		public string MnemonicBinarySeed => this[3];
		public string ParentPrivateKey => this[4];
		public string ParentDerivationPath => this[5];
		public string IndexString => this[6];
		public bool IsHardenedChild => IndexString.EndsWith('H');
		public uint Index => IsHardenedChild ? uint.Parse(IndexString[..^1]) ^ 0x8000_0000 : uint.Parse(IndexString);
		public string DerivationPath => ParentDerivationPath == string.Empty && IndexString == string.Empty ? "m" : string.Format("{0}/{1}", ParentDerivationPath, IndexString);
		public string PublicKey => this[7];
		public string PrivateKey => this[8];
	}
}
