using System;
using System.Numerics;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// Creates a private key RSAParameters from two prime numbers.
		/// </summary>
		/// <param name="p">A prime number that is half the bit length of <paramref name="publicModulusBitLength"/>.</param>
		/// <param name="q">A prime number that is half the bit length of <paramref name="publicModulusBitLength"/>.</param>
		/// <param name="publicModulusBitLength">The desired bit length of the public modulus (i.e. this parameter would be 4096 for RSA-4096).</param>
		/// <returns>A valid <see cref="RSAParameters"/> if all checks pass; otherwise, <see langword="null"/>.</returns>
		public static RSAParameters? GetRSAParametersForPrimes(BigPrime p, BigPrime q, int publicModulusBitLength)
		{
			ArgumentNullException.ThrowIfNull(p);
			ArgumentNullException.ThrowIfNull(q);
			// Calculate the expected bit length of P and Q (half the key length)
			int privatePrimesBitLength = publicModulusBitLength / 2;
			// Our prime generation should ensure the primes P and Q have the most significant bit set as 1, so they should be exactly half the key length
			if (p.BitLength != privatePrimesBitLength || q.BitLength != privatePrimesBitLength)
			{
				return null;
			}
			// The only common divisor of P and Q should be 1
			else if (BigInteger.GreatestCommonDivisor(p, q) != BigInteger.One)
			{
				return null;
			}
			// P - 1
			BigInteger pMinusOne = p - 1;
			// Q - 1
			BigInteger qMinusOne = q - 1;
			// GCD(P - 1, Q - 1)
			BigInteger gcdN = BigInteger.GreatestCommonDivisor(pMinusOne, qMinusOne);
			// phi(N)
			BigInteger phiN = pMinusOne * qMinusOne;
			// lambda(N)
			BigInteger lambdaN = phiN / gcdN;
			// Create a BigInteger for E
			BigInteger publicExponent = new(ParameterE);
			// The only common divisor of E and lambda(N) should be 1
			if (BigInteger.GreatestCommonDivisor(publicExponent, lambdaN) != BigInteger.One)
			{
				return null;
			}
			// Calculate N
			BigInteger publicModulus = p * q;
			// P and Q should not be too close together
			BigInteger minimumDistance = BigInteger.One << (privatePrimesBitLength - 100);
			if (BigInteger.Abs(p - q) <= minimumDistance)
			{
				return null;
			}
			// Calculate D
			BigInteger privateModulus = BigIntegerExtensions.ModInverse(publicExponent, lambdaN);
			// The only common divisor of D and lambda(N) should be 1
			if (BigInteger.GreatestCommonDivisor(privateModulus, lambdaN) != BigInteger.One)
			{
				return null;
			}
			// D should be greater than or equal to 1, and less than or equal to lambda(n)
			if (privateModulus < 1 || privateModulus > lambdaN)
			{
				return null;
			}
			// Sanity check D
			// RFC 8017: e * d == 1 (mod \lambda(n)))
			if (publicExponent * privateModulus % lambdaN != BigInteger.One)
			{
				return null;
			}

			// The bit length of D should be close to the bit length of N: D should not be less than half the size of N
			double dBitLength = privateModulus.GetBitLength();
			double nBitLength = publicModulus.GetBitLength();
			double dnRatio = dBitLength / nBitLength;
			if (dnRatio < 0.5)
			{
				return null;
			}
			// Calculate DP
			BigInteger dp = BigIntegerExtensions.ModInverse(publicExponent, pMinusOne);
			// Sanity check DP
			// RFC 8017: e * dP == 1 (mod (p-1))
			if (publicExponent * dp % pMinusOne != BigInteger.One)
			{
				return null;
			}
			// Calculate DQ
			BigInteger dq = BigIntegerExtensions.ModInverse(publicExponent, qMinusOne);
			// Sanity check DQ
			// RFC 8017: e * dQ == 1 (mod (q-1))
			if (publicExponent * dq % qMinusOne != BigInteger.One)
			{
				return null;
			}
			// Calculate InverseQ
			BigInteger inverseQ = BigIntegerExtensions.ModInverse(q, p);
			// Sanity-check InverseQ
			// RFC 8017: q * qInv == 1 (mod p)
			if (q * inverseQ % p != BigInteger.One)
			{
				return null;
			}

			// All checks should be performed above this point

			// Convert public modulus length to bytes
			int publicModulusByteLength = publicModulusBitLength / 8;
			// Convert private primes length to bytes
			int privatePrimesByteLength = privatePrimesBitLength / 8;
			// Create a new RSAParameters
			RSAParameters rsaParams = new()
			{
				Modulus = PadBigEndianArrayWithLeadingZeros(publicModulus, publicModulusByteLength),
				Exponent = publicExponent.ToByteArray(true, true),
				D = PadBigEndianArrayWithLeadingZeros(privateModulus, publicModulusByteLength),
				P = PadBigEndianArrayWithLeadingZeros(p, privatePrimesByteLength),
				Q = PadBigEndianArrayWithLeadingZeros(q, privatePrimesByteLength),
				DP = PadBigEndianArrayWithLeadingZeros(dp, privatePrimesByteLength),
				DQ = PadBigEndianArrayWithLeadingZeros(dq, privatePrimesByteLength),
				InverseQ = PadBigEndianArrayWithLeadingZeros(inverseQ, privatePrimesByteLength)
			};

			// Return the RSAParameters
			return rsaParams;
		}
	}
}
