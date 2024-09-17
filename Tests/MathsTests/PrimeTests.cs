using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
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
		/// A simple test of <see cref="Lucas"/> using a small number of primes.
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
				Assert.IsTrue(Lucas.IsProbablePrime(bigPrime));
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
	}
}
