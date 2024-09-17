using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths.PrimalityTests;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public partial class BigPrime
	{
		/// <summary>
		/// Tests primality for the current <see cref="BigPrime"/> object, and updates the <see cref="IsProbablePrime"/> property.
		/// </summary>
		/// <param name="compatibilityFlags">Flags to indicate how numbers should be primality tested. <see langword="null"/> is currently treated as <see cref="StandardRSA.Compatibility.None"/>.</param>
		/// <param name="randomNumberGenerator">The RNG to use for generating Miller-Rabin witness numbers.</param>
		/// <param name="millerRabinRounds">The number of rounds of Miller-Rabin testing.</param>
		/// <remarks>
		/// <para>If <see cref="BigPrime.IsPerfectSquare"/> is <see langword="true"/>, primality testing will not be performed.</para>
		/// <para>If <paramref name="compatibilityFlags"/> includes <see cref="StandardRSA.Compatibility.PerformMillerRabinTesting"/>, either combine it with the
		///  <see cref="StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds"/> flag and set <paramref name="millerRabinRounds"/> to <see langword="null"/>,
		///  or specify the number of <paramref name="millerRabinRounds"/>.</para>
		/// <para>If <paramref name="compatibilityFlags"/> includes <see cref="StandardRSA.Compatibility.PerformLucasTesting"/>, a Lucas test will be performed.</para>
		/// </remarks>
		/// <returns>
		///  <para><see langword="true"/> if probably prime.</para>
		///  <para><see langword="false"/> if likely composite.</para>
		///  <para><see langword="null"/> if <see cref="IsPerfectSquare"/> is <see langword="false"/>
		///   and <paramref name="compatibilityFlags"/> did not include a primality test flag.</para>
		/// </returns>
		public bool? CheckPrimality(StandardRSA.Compatibility? compatibilityFlags = null, RandomNumberGenerator? randomNumberGenerator = null, int? millerRabinRounds = null)
		{
			if (IsPerfectSquare)
			{
				_isProbablePrime = false;
				return false;
			}

			compatibilityFlags ??= CompatibilityFlags;
			bool performMillerRabinTesting = compatibilityFlags.Value.HasFlag(StandardRSA.Compatibility.PerformMillerRabinTesting);
			bool performLucasTesting = compatibilityFlags.Value.HasFlag(StandardRSA.Compatibility.PerformLucasTesting);

			if (!performMillerRabinTesting && !performLucasTesting)
			{
				_isProbablePrime = null;
				return null;
			}

			bool tempResult = IsProbablePrime ?? true;

			if (tempResult && performMillerRabinTesting)
			{
				bool millerRabinIsProbablyPrime = MillerRabin.IsProbablePrime(this, compatibilityFlags.Value, randomNumberGenerator, millerRabinRounds);
				CompatibilityFlags |= StandardRSA.Compatibility.PerformMillerRabinTesting;
				//CompatibilityFlags ^= millerRabinRounds is not null ? StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds : StandardRSA.Compatibility.None;
				if (millerRabinIsProbablyPrime == false)
				{
					HasFactor = false;
					_isProbablePrime = false;
					return false;
				}
				tempResult = tempResult && millerRabinIsProbablyPrime;
			}
			if (tempResult && performLucasTesting)
			{
				bool lucasIsProbablyPrime = Lucas.IsProbablePrime(this);
				CompatibilityFlags |= StandardRSA.Compatibility.PerformLucasTesting;
				if (lucasIsProbablyPrime == false)
				{
					HasFactor = true;
					_isProbablePrime = false;
					return false;
				}
				tempResult = tempResult && lucasIsProbablyPrime;
			}
			_isProbablePrime = tempResult;
			return tempResult;
		}
	}
}
