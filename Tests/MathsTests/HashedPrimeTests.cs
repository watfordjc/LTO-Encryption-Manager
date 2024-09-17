using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	public partial class PrimeTests
	{
		private const int lineLength = 83;
		private const int fullGroupSize = 23;

		/// <summary>
		/// A test to find 5,000 consecutive prime numbers below 2^32, with zero false positivies and zero false negatives.
		/// </summary>
		/// <returns></returns>
		[TestMethod]
		public async Task FindPrimesWithinPrimeGroupTest()
		{
			// Get a random number between 0 and 20 inclusive - there are 20 blocks of 10,000,000 primes and a final block of 2,280,220 primes (all blocks have a K5 group)
			int m10Offset = RandomNumberGenerator.GetInt32(21);
			// Use group size of 5,000 primes - quick test as there's only one K5 group per block of 10,000,000 primes
			PrimeGroupSize groupSize = PrimeGroupSize.K5;
			// Find and hash all primes within that group
			await FindPrimesWithinPrimeGroup(m10Offset, groupSize).ConfigureAwait(false);
		}

		public enum PrimeGroupSize
		{
			/// <summary>
			/// A group containing 0 prime numbers.
			/// </summary>
			None = 0,
			/// <summary>
			/// A group containing 5K prime numbers.
			/// </summary>
			K5 = 5_000,
			/// <summary>
			/// A group containing 10K prime numbers.
			/// </summary>
			K10 = 10_000,
			/// <summary>
			/// A group containing 25K prime numbers.
			/// </summary>
			K25 = 25_000,
			/// <summary>
			/// A group containing 50K prime numbers.
			/// </summary>
			K50 = 50_000,
			/// <summary>
			/// A group containing 100K prime numbers.
			/// </summary>
			K100 = 100_000,
			/// <summary>
			/// A group containing 250K prime numbers.
			/// </summary>
			K250 = 250_000,
			/// <summary>
			/// A group containing 500K prime numbers.
			/// </summary>
			K500 = 500_000,
			/// <summary>
			/// A group containing 1M prime numbers.
			/// </summary>
			M1 = 1_000_000,
			/// <summary>
			/// A group containing 280,220 prime numbers (the final group).
			/// </summary>
			Last = 280_220,
			/// <summary>
			/// All groups in a block (10M prime numbers).
			/// </summary>
			/// <remarks>The value of -1 is because enum is an int by default and 10M is too big.</remarks>
			All = -1
		}

		private static int[] GetGroupOffsets(PrimeGroupSize size)
		{
			// Each 10,000,000 block of primes is split into 23 groups, with each group given a line in the CSV file
			// The repeating pattern of groups is: {5K, 10K, 10K, 25K, 50K, 50K, 50K, 100K, 100K, 100K, 250K, 250K, 500K, 500K, 500K, 500K, 1M, 1M, 1M, 1M, 1M, 1M, 1M}
			// Total primes (group size) per 10M block: 5K (5K), 20K (10K), 25K (25K), 150K (50K), 300K (100K), 500K (250K), 2M (500K), 7M (1M)
			return size switch
			{
				PrimeGroupSize.None => [],
				PrimeGroupSize.K5 => [0],
				PrimeGroupSize.K10 => [1, 2],
				PrimeGroupSize.K25 => [3],
				PrimeGroupSize.K50 => [4, 5, 6],
				PrimeGroupSize.K100 => [7, 8, 9],
				PrimeGroupSize.K250 => [10, 11],
				PrimeGroupSize.K500 => [12, 13, 14, 15],
				PrimeGroupSize.M1 => [16, 17, 18, 19, 20, 21, 22],
				PrimeGroupSize.Last => [16],
				PrimeGroupSize.All => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],
				_ => []
			};
		}

		public static ulong GetGroupSizeNumber(PrimeGroupSize groupSize)
		{
			// A full block contains all groups, or 10,000,000 prime numbers
			if (groupSize == PrimeGroupSize.All)
			{
				return 10_000_000;
			}
			// All other groups contain the number of prime numbers equal to the PrimeGroupSize's value
			else
			{
				return (ulong)groupSize;
			}
		}

		public static async Task<string[]?> GetPrimeHashes(PrimeGroupSize groupSize, long? m10GroupOffset)
		{
			// Open the CSV file
			using FileStream openStream = File.OpenRead(@"data/32bit-prime-number-group-hashes.csv");
			// Get the 1-based line count of the file (all lines have the same length)
			int lineCount = (int)((openStream.Length + 1) / lineLength);
			// Get the number of full blocks of 10M primes, and the remaining line count
			(int fullGroups, int remainder) = int.DivRem(lineCount, fullGroupSize);

			// Calculate the file offset for the 10M block
			long fileOffset = m10GroupOffset * fullGroupSize * lineLength ?? 0;
			// Get the line offsets for all lines within the group
			int[] groupOffsets = GetGroupOffsets(groupSize);

			// Check the first line offset for the group is not out of bounds of the file
			if ((fullGroups == 0 || m10GroupOffset == fullGroups) && groupOffsets[0] > remainder)
			{
				return null;
			}
			// The last 10M group only contains a partial 1M group, the Final group. If the 10M group and PrimeGroupSize are compatible, return the requested lines of the file
			else if (m10GroupOffset < fullGroups || m10GroupOffset == fullGroups && groupSize != PrimeGroupSize.All && groupSize != PrimeGroupSize.M1)
			{
				// Calculate the seek offset (from the start of the file)
				long seekOffset = fileOffset + groupOffsets[0] * lineLength;
				// Store the number of lines we want in a variable
				long linesWanted = groupOffsets.Length;
				// Create a buffer to hold those lines
				Memory<byte> buffer = new byte[linesWanted * lineLength];
				// Seek if we need to
				if (seekOffset > 0)
				{
					openStream.Seek(seekOffset, SeekOrigin.Begin);
				}
				// Read the lines into the buffer
				await openStream.ReadExactlyAsync(buffer).ConfigureAwait(false);
				// Split the buffer into a string array, with each string containing a line
				return Encoding.UTF8.GetString(buffer.Span).Split('\n', StringSplitOptions.RemoveEmptyEntries);
			}
			return null;
		}

		private async Task FindPrimesWithinPrimeGroup(int m10Offset, PrimeGroupSize groupSize)
		{
			string[]? lines = await GetPrimeHashes(groupSize, m10Offset).ConfigureAwait(false);
			Assert.IsNotNull(lines);
			Assert.IsNotNull(lines);

			Trace.WriteLine($"Searching for and primality testing {lines.Length} {string.Format(CultureInfo.CurrentCulture, "{0}", lines.Length > 1 ? "chunks" : "chunk")} of numbers with {string.Format(CultureInfo.CurrentCulture, "{0}", groupSize != PrimeGroupSize.All ? "each chunk" : "all chunks combined")} containing {GetGroupSizeNumber(groupSize):N0} prime numbers. The chunks being tested are within a larger chunk of {10_000_000:N0} primes that start at the nth prime number where n is {m10Offset * 10000000 + 2:N0} ({nameof(m10Offset)}={m10Offset}).");
			Trace.WriteLine("");

			Parallel.For(0, lines.Length, (Action<int>)(index =>
			{
				string[] csvValues = lines[index].Split(',', StringSplitOptions.None);
				// The first column in the file is the first prime number in the group
				uint minPrime = BitConverter.ToUInt32(ByteEncoding.FromNetworkByteOrderHexString(csvValues[0]));
				// The second column in the file is the last prime number in the group
				uint maxPrime = BitConverter.ToUInt32(ByteEncoding.FromNetworkByteOrderHexString(csvValues[1]));
				// The third column in the file is the SHA2-256 hash of all primes (litte endian, 4-byte uint) in the group
				byte[] primesHash = ByteEncoding.FromHexString(csvValues[2]);
				byte[] testingHash = new byte[SHA256.HashSizeInBytes];
				byte[] currentPrimeBytes = new byte[4];
				using SHA256 testingHasher = SHA256.Create();
				StringBuilder sb = new();
				int primeCount = 0;
#if PRIMES_FILE
				int missedPrimeCount = 0;
				uint expectedNextPrime = GetPrime(m10Offset, groupSize, index, primeCount + missedPrimeCount);
#endif
				// Initialise counters to keep track of divisibility by the first 10 prime numbers
				bool next2 = minPrime % 2 == 0;
				uint next3 = 3 - minPrime % 3;
				uint next5 = 5 - minPrime % 5;
				uint next7 = 7 - minPrime % 7;
				uint next11 = 11 - minPrime % 11;
				uint next13 = 13 - minPrime % 13;
				uint next17 = 17 - minPrime % 17;
				uint next19 = 19 - minPrime % 19;
				uint next23 = 23 - minPrime % 23;
				uint next29 = 29 - minPrime % 29;
				uint startSkippingFrom = 29;
				// From the first prime in the group through to the last, iterate on every integer
				// Decrease divisibility counters at the end of each iteration
				for (uint i = minPrime; i <= maxPrime; i++, next2 = !next2, next3--, next5--, next7--, next11--, next13--, next17--, next19--, next23--, next29--)
				{
					// If this number is divisible by one of the first 10 prime numbers
					if (next2 || next3 == 0 || next5 == 0 || next7 == 0 || next11 == 0 || next13 == 0 || next17 == 0 || next19 == 0 || next23 == 0 || next29 == 0)
					{
						// Reset any applicable counters
						if (next3 == 0) { next3 = 3; }
						if (next5 == 0) { next5 = 5; }
						if (next7 == 0) { next7 = 7; }
						if (next11 == 0) { next11 = 11; }
						if (next13 == 0) { next13 = 13; }
						if (next17 == 0) { next17 = 17; }
						if (next19 == 0) { next19 = 19; }
						if (next23 == 0) { next23 = 23; }
						if (next29 == 0) { next29 = 29; }
						// Skip to the next iteration, if 'i' is not one of the first 10 prime numbers
						if (i > startSkippingFrom) { continue; }
					}
					BigPrime potentialPrime = new(i,
						StandardRSA.Compatibility.PerformMillerRabinTesting |
						StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds |
						StandardRSA.Compatibility.PerformLucasTesting);
					potentialPrime.CheckPrimality();
#if PRIMES_FILE
					if (Debugger.IsAttached && i == expectedNextPrime && !potentialPrime.IsProbablyPrime.GetValueOrDefault(false))
					{
						Trace.WriteLine($"False Positive: The number {i:N0} is prime but {nameof(potentialPrime.IsProbablyPrime)}={potentialPrime.IsProbablyPrime}!");
						missedPrimeCount++;
						expectedNextPrime = GetPrime(m10Offset, groupSize, index, primeCount + missedPrimeCount);
					}
					else if (Debugger.IsAttached && i < expectedNextPrime && potentialPrime.IsProbablyPrime.GetValueOrDefault(false))
					{
						Trace.WriteLine($"False Negative: The number {i:N0} is not prime but {nameof(potentialPrime.IsProbablyPrime)}={potentialPrime.IsProbablyPrime}! {nameof(expectedNextPrime)}={expectedNextPrime:N0}");
						currentPrimeBytes = BitConverter.GetBytes(i);
						testingHasher.TransformBlock(currentPrimeBytes, 0, currentPrimeBytes.Length, null, 0);
					}
					else if (Debugger.IsAttached && i > expectedNextPrime && potentialPrime.IsProbablyPrime.GetValueOrDefault(false))
					{
						while (i != expectedNextPrime)
						{
							Trace.WriteLine($"False Positive: The number {expectedNextPrime:N0} is prime but {nameof(expectedNextPrime)}={i:N0} - it was skipped over!");
							missedPrimeCount++;
							expectedNextPrime = GetPrime(m10Offset, groupSize, index, primeCount + missedPrimeCount);
						}
						primeCount++;
						expectedNextPrime = GetPrime(m10Offset, groupSize, index, primeCount + missedPrimeCount);
					}
					else
#endif
					if (potentialPrime.IsProbablePrime.GetValueOrDefault(false))
					{
						//sb.Append(CultureInfo.InvariantCulture, $"{i} ");
						currentPrimeBytes = BitConverter.GetBytes(i);
						testingHasher.TransformBlock(currentPrimeBytes, 0, currentPrimeBytes.Length, null, 0);
						primeCount++;
#if PRIMES_FILE
						if (Debugger.IsAttached)
						{
							expectedNextPrime = GetPrime(m10Offset, groupSize, index, primeCount + missedPrimeCount);
						}
#endif
					}
				}
				//sb.Append('\n');
				testingHasher.TransformFinalBlock([], 0, 0);
				Assert.IsNotNull(testingHasher.Hash);
				sb.AppendFormat(CultureInfo.InvariantCulture, "For prime chunk containing primes 0x{0} through 0x{1}:\n", csvValues[0], csvValues[1]);
				sb.AppendLine(CultureInfo.CurrentCulture, $"Primes found: {primeCount:N0}/{GetGroupSizeNumber(groupSize):N0}");
				sb.AppendLine(CultureInfo.InvariantCulture, $"Result: {csvValues[2]}");
				sb.AppendLine(CultureInfo.InvariantCulture, $"Expected: {ByteEncoding.ToHexString(testingHasher.Hash)}");
				Trace.WriteLine(sb.ToString());
				Assert.IsTrue(primesHash.SequenceEqual(testingHasher.Hash));
			}));
		}
	}
}
