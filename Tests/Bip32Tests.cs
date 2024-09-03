using CryptHash.Net.Encoding;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests
{
	[TestClass]
	public class Bip32Tests
	{
		public static async Task<Collection<Models.Bip32TestVector>?> GetMasterNodeTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/bip0032-master-node-vectors.json");
			Models.Bip32TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip32TestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.Vectors;
		}

		public static async Task<Collection<Models.Bip32TestVector>?> GetChildNodeTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/bip0032-child-node-vectors.json");
			Models.Bip32TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip32TestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.Vectors;
		}

		public static async Task<Collection<Models.Bip32TestVector>?> PrivateKeyOutOfRangeTestVectorsAsync()
		{
			using FileStream openStream = File.OpenRead(@"data/bip0032-error-01-vectors.json");
			Models.Bip32TestVectorsRoot? jsonRoot = await JsonSerializer.DeserializeAsync<Models.Bip32TestVectorsRoot>(openStream).ConfigureAwait(false);
			openStream.Close();
			return jsonRoot?.Vectors;
		}

		[TestMethod]
		public async Task GetMasterNodeFromBinarySeedTest()
		{
			string masterNodeDerivationPath = "m";
			IEnumerable<Models.Bip32TestVector>? testVectors = await GetMasterNodeTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node? masterNode = Bip32.GetMasterNodeFromBinarySeed(Utils.Encodings.FromHexString(testVector.MnemonicBinarySeed), testVector.PublicKeyPrefixValue, testVector.PrivateKeyPrefixValue, testVector.CurveName);
				Assert.IsNotNull(masterNode);
				Assert.IsTrue(masterNode.IsMasterNode);
				Assert.IsTrue(masterNode.IsHardenedNode);
				Assert.AreEqual(masterNodeDerivationPath, masterNode.DerivationPath);
				Assert.AreEqual(testVector.DerivationPath, masterNode.DerivationPath);
				Assert.IsNull(masterNode.ParentFingerprint);
				Assert.IsNull(masterNode.ChildNumber);
				Assert.AreEqual(masterNode.Depth, 0);
				Assert.IsNotNull(masterNode.KeyIdentifier);
				Assert.IsNotNull(masterNode.Fingerprint);
				Assert.AreEqual(BitConverter.ToUInt32(Utils.Encodings.FromNetworkByteOrderHexString(masterNode.KeyIdentifier[..8])), masterNode.Fingerprint);
				Assert.IsNotNull(masterNode.PrivateKeySerialised);
				Assert.AreEqual(testVector.PrivateKey, new(masterNode.PrivateKeySerialised));
				Assert.IsNotNull(masterNode.PublicKeySerialised);
				Assert.AreEqual(testVector.PublicKey, new(masterNode.PublicKeySerialised));
				Assert.IsTrue(masterNode.IsInitialised);
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public async Task GetMasterNodeFromSerialisedPrivateKeyTest()
		{
			string masterNodeDerivationPath = "m";
			IEnumerable<Models.Bip32TestVector>? testVectors = await GetMasterNodeTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node masterNode = Bip32.GetMasterNodeFromSerialisedPrivateKey(testVector.PrivateKey);
				Assert.IsTrue(masterNode.IsMasterNode);
				Assert.IsTrue(masterNode.IsHardenedNode);
				Assert.AreEqual(masterNodeDerivationPath, masterNode.DerivationPath);
				Assert.AreEqual(testVector.DerivationPath, masterNode.DerivationPath);
				Assert.IsNull(masterNode.ParentFingerprint);
				Assert.IsNull(masterNode.ChildNumber);
				Assert.AreEqual(masterNode.Depth, 0);
				Assert.IsNotNull(masterNode.KeyIdentifier);
				Assert.IsNotNull(masterNode.Fingerprint);
				Assert.AreEqual(BitConverter.ToUInt32(Utils.Encodings.FromNetworkByteOrderHexString(masterNode.KeyIdentifier[..8])), masterNode.Fingerprint);
				Assert.IsNotNull(masterNode.PrivateKeySerialised);
				Assert.AreEqual(testVector.PrivateKey, new(masterNode.PrivateKeySerialised));
				Assert.IsNotNull(masterNode.PublicKeySerialised);
				Assert.AreEqual(testVector.PublicKey, new(masterNode.PublicKeySerialised));
				Assert.IsTrue(masterNode.IsInitialised);
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public async Task GetChildNodeTest()
		{
			IEnumerable<Models.Bip32TestVector>? testVectors = await GetChildNodeTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node parentNode = new(testVector.ParentPrivateKey, testVector.ParentDerivationPath);
				Assert.IsNotNull(parentNode);
				Assert.IsTrue(parentNode.IsInitialised);
				Assert.IsNotNull(parentNode.VersionPrefixPrivate);
				uint versionBytesPrivate = (uint)parentNode.VersionPrefixPrivate;
				ECDomainParameters? domainParams = Bip32.GetDomainParameters(versionBytesPrivate);
				Assert.IsNotNull(domainParams);
				Bip32Node? childNode = Bip32Node.GetChildNode(domainParams, ref parentNode, testVector.Index);
				Assert.IsNotNull(childNode);
				Assert.IsFalse(childNode.IsMasterNode);
				Assert.AreEqual(testVector.IsHardenedChild, childNode.IsHardenedNode);
				Assert.AreEqual(testVector.DerivationPath, childNode.DerivationPath);
				Assert.IsNotNull(childNode.ParentFingerprint);
				Assert.IsNotNull(childNode.ChildNumber);
				Assert.AreEqual(childNode.Depth, parentNode.Depth + 1);
				Assert.IsNotNull(childNode.KeyIdentifier);
				Assert.IsNotNull(childNode.Fingerprint);
				Assert.AreEqual(parentNode.Fingerprint, childNode.ParentFingerprint);
				Assert.AreEqual(BitConverter.ToUInt32(Utils.Encodings.FromNetworkByteOrderHexString(childNode.KeyIdentifier[..8])), childNode.Fingerprint);
				Assert.IsNotNull(childNode.PrivateKeySerialised);
				Assert.AreEqual(testVector.PrivateKey, new(childNode.PrivateKeySerialised));
				Assert.IsNotNull(childNode.PublicKeySerialised);
				Assert.AreEqual(testVector.PublicKey, new(childNode.PublicKeySerialised));
				Assert.IsTrue(childNode.IsInitialised);
				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			});
		}

		[TestMethod]
		public void InvalidKeyTest()
		{
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm")); // (pubkey version / prvkey mismatch)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH")); // (prvkey version / pubkey mismatch)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn")); // (invalid pubkey prefix 04)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ")); // (invalid prvkey prefix 04)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4")); // (invalid pubkey prefix 01)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J")); // (invalid prvkey prefix 01)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv")); // (zero depth with non-zero parent fingerprint)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ")); // (zero depth with non-zero parent fingerprint)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN")); // (zero depth with non-zero index)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8")); // (zero depth with non-zero index)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4")); // (unknown extended key version)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9")); // (unknown extended key version)
			Assert.ThrowsException<ArgumentOutOfRangeException>(() => _ = new Bip32Node("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx")); // (private key n not in 1..n-1)
			Assert.ThrowsException<ArgumentOutOfRangeException>(() => _ = new Bip32Node("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G")); // (private key n not in 1..n-1)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY")); // (invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007)
			Assert.ThrowsException<ArgumentException>(() => _ = new Bip32Node("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL")); // (invalid checksum)
		}
	}
}
