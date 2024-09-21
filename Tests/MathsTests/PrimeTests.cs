using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Tests.BIPTests;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths.PrimalityTests;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	[TestClass]
	public partial class PrimeTests
	{
		/// <summary>
		/// A simple test of <see cref="MillerRabin"/> using a small number of primes.
		/// </summary>
		/// <returns>A <see cref="Task"/>.</returns>
		[TestMethod]
		public async Task SimpleMillerRabinTest()
		{
			List<uint> primes = new(BigPrime.First100Primes);
			primes.AddRange(await GetPrimes().ConfigureAwait(false));
			foreach (uint primeNumber in primes)
			{
				BigPrime bigPrime = new(primeNumber, StandardRSA.Compatibility.Default);
				Assert.IsTrue(MillerRabin.IsProbablePrime(bigPrime, bigPrime.CompatibilityFlags));
			}
		}

		/// <summary>
		/// A simple test of <see cref="LucasLehmer"/> using a small number of primes and Mersenne primes.
		/// </summary>
		/// <returns>A <see cref="Task"/>.</returns>
		[TestMethod]
		public async Task SimpleLucasTest()
		{
			List<uint> primes = new(BigPrime.First100Primes);
			primes.AddRange(await GetPrimes().ConfigureAwait(false));
			foreach (uint primeNumber in primes)
			{
				BigPrime bigPrime = new(primeNumber, StandardRSA.Compatibility.None);
				Assert.IsTrue(LucasLehmer.IsProbablePrime(bigPrime));
			}
			BigInteger[] mersennePrimes = [3, 7, 31, 127, 8191, 131071, 524287, 2147483647, 2305843009213693951,
				BigInteger.Parse("618970019642690137449562111", NumberStyles.None, CultureInfo.InvariantCulture),
				BigInteger.Parse("162259276829213363391578010288127", NumberStyles.None, CultureInfo.InvariantCulture),
				BigInteger.Parse("170141183460469231731687303715884105727", NumberStyles.None, CultureInfo.InvariantCulture)
				];
			foreach (BigInteger mersenneNumber in mersennePrimes)
			{
				BigPrime bigPrime = new(mersenneNumber, StandardRSA.Compatibility.None);
				Assert.IsTrue(LucasLehmer.IsProbablePrime(bigPrime));
			}
		}

		/// <summary>
		/// Extracts the first and last prime number of every group of primes in the CSV file.
		/// </summary>
		/// <returns>A collection of prime numbers that are all less than 2^32.</returns>
		public static async Task<Collection<uint>> GetPrimes()
		{
			using FileStream openStream = File.OpenRead(@"data/32bit-prime-number-group-hashes.csv");
			int lineCount = (int)((openStream.Length + 1) / lineLength);
			string[] lines = [];
			Collection<uint> primes = [];

			for (int i = 0; i < lineCount; i++)
			{
				Memory<byte> buffer = new byte[lineLength];
				await openStream.ReadExactlyAsync(buffer).ConfigureAwait(false);
				lines = Encoding.UTF8.GetString(buffer.Span).Split('\n', StringSplitOptions.RemoveEmptyEntries);
				string[] csvValues = lines[0].Split(',', StringSplitOptions.None);
				primes.Add(BitConverter.ToUInt32(ByteEncoding.FromNetworkByteOrderHexString(csvValues[0])));
				primes.Add(BitConverter.ToUInt32(ByteEncoding.FromNetworkByteOrderHexString(csvValues[1])));
			}
			return primes;
		}

		/// <summary>
		/// A test to check <see cref="BigPrime"/> creation using a <see cref="Shake256DRNG"/> results in correct <see cref="BigPrime"/> property values.
		/// </summary>
		/// <returns>A <see cref="Task"/>.</returns>
		[TestMethod]
		public async Task GetBitLengthPrimesFromDRNGTest()
		{
			IEnumerable<Models.Bip85DrngEntropyTestVector>? testVectors = await Bip85Tests.GetDrngEntropyTestVectorsAsync().ConfigureAwait(false);
			Assert.IsNotNull(testVectors);
			using SemaphoreSlim semaphore = new(1);
			_ = Parallel.ForEach(testVectors, (Action<Models.Bip85DrngEntropyTestVector>)(testVector =>
			{
				if (Debugger.IsAttached)
				{
					semaphore.Wait();
				}
				Bip32Node rootNode = Bip85Tests.GetBip32RootNode(testVector.MasterNodePrivateKey);
				Bip32Node? derivationNode = Bip85Tests.GetBip32NodeFromDerivationPath(rootNode, testVector.DerivationPath);
				Assert.IsNotNull(derivationNode);
				Assert.IsFalse(derivationNode.IsMasterNode);
				Assert.AreEqual(testVector.DerivationPath, derivationNode.DerivationPath);
				Assert.IsNotNull(derivationNode.PrivateKeySerialised);
				Assert.AreEqual(testVector.PrivateKeyHex, new(ByteEncoding.ToHexString([.. derivationNode.Left])));
				ReadOnlySpan<byte> entropyFromK = Bip85.GetEntropy(derivationNode, 64);
				Assert.AreEqual(testVector.EntropyHex, ByteEncoding.ToHexString([.. entropyFromK]));

				using Shake256DRNG shake256DRNG = new(derivationNode);
				int[] bitLengths = [512, 1024, 1536, 2048];
				BigPrime potentialPrime;
				foreach (int bitLength in bitLengths)
				{
					potentialPrime = BigPrime.Create(bitLength, StandardRSA.Compatibility.Default, shake256DRNG, null);
					Assert.AreEqual(bitLength, potentialPrime.BitLength);
					Assert.AreEqual(bitLength, potentialPrime.UnsignedByteCount * 8);
					Assert.IsFalse(potentialPrime.IsEven);
					Assert.IsTrue(potentialPrime.IsOdd);
					Assert.IsFalse(potentialPrime.IsSmallPrime);
					Assert.IsFalse(potentialPrime.IsOne);
					Assert.IsFalse(potentialPrime.IsZero);
					Assert.IsFalse(potentialPrime.IsPerfectSquare);
					Assert.IsNull(potentialPrime.HasFactor);
					Assert.IsFalse(potentialPrime.IsFermatNumber);
					Assert.IsFalse(potentialPrime.IsMersenneNumber);
					Assert.IsFalse(potentialPrime.IsPossiblyWeakPrime);
					Assert.IsTrue((bool?)potentialPrime.IsProbablePrime);
				}

				if (Debugger.IsAttached)
				{
					semaphore.Release();
				}
			}));
		}
	}
}
