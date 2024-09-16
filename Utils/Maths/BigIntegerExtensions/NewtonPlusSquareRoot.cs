using System;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Calculates the integer square root of a <paramref name="number"/> using the 'NewtonPlus' method.
		/// </summary>
		/// <param name="number">The number to calculate the square root of.</param>
		/// <returns>The integer square root.</returns>
		/// <remarks>
		/// <para>License information: 'NewtonPlus' square root function by Ryan Scott White. MIT License. See project/solution LICENSE file.</para>
		/// </remarks>
		private static BigInteger NewtonPlusSquareRoot(this BigInteger number)
		{
			if (number < 144838757784765629)    // 1.448e17 = ~1<<57
			{
				uint vInt = (uint)Math.Sqrt((ulong)number);
				if ((number >= 4503599761588224) && ((ulong)vInt * vInt > (ulong)number))  // 4.5e15 =  ~1<<52
				{
					vInt--;
				}
				return vInt;
			}

			double xAsDub = (double)number;
			if (xAsDub < 8.5e37)   //  long.max*long.max
			{
				ulong vInt = (ulong)Math.Sqrt(xAsDub);
				BigInteger v = (vInt + ((ulong)(number / vInt))) >> 1;
				return (v * v <= number) ? v : v - 1;
			}

			if (xAsDub < 4.3322e127)
			{
				BigInteger v = (BigInteger)Math.Sqrt(xAsDub);
				v = (v + (number / v)) >> 1;
				if (xAsDub > 2e63)
				{
					v = (v + (number / v)) >> 1;
				}
				return (v * v <= number) ? v : v - 1;
			}

			int xLen = (int)number.GetBitLength();
			int wantedPrecision = (xLen + 1) / 2;
			int xLenMod = xLen + (xLen & 1) + 1;

			//////// Do the first Sqrt on hardware ////////
			long tempX = (long)(number >> (xLenMod - 63));
			double tempSqrt1 = Math.Sqrt(tempX);
			ulong valLong = (ulong)BitConverter.DoubleToInt64Bits(tempSqrt1) & 0x1fffffffffffffL;
			if (valLong == 0)
			{
				valLong = 1UL << 53;
			}

			////////  Classic Newton Iterations ////////
			BigInteger val = ((BigInteger)valLong << 52) + (number >> xLenMod - (3 * 53)) / valLong;
			int size = 106;
			for (; size < 256; size <<= 1)
			{
				val = (val << (size - 1)) + (number >> xLenMod - (3 * size)) / val;
			}

			if (xAsDub > 4e254) // 4e254 = 1<<845.76973610139
			{
				int numOfNewtonSteps = BitOperations.Log2((uint)(wantedPrecision / size)) + 2;

				//////  Apply Starting Size  ////////
				int wantedSize = (wantedPrecision >> numOfNewtonSteps) + 2;
				int needToShiftBy = size - wantedSize;
				val >>= needToShiftBy;
				size = wantedSize;
				do
				{
					////////  Newton Plus Iterations  ////////
					int shiftX = xLenMod - (3 * size);
					BigInteger valSqrd = (val * val) << (size - 1);
					BigInteger valSU = (number >> shiftX) - valSqrd;
					val = (val << size) + (valSU / val);
					size *= 2;
				} while (size < wantedPrecision);
			}

			/////// There are a few extra digits here, lets save them ///////
			int oversidedBy = size - wantedPrecision;
			BigInteger saveDroppedDigitsBI = val & ((BigInteger.One << oversidedBy) - 1);
			int downby = (oversidedBy < 64) ? (oversidedBy >> 2) + 1 : (oversidedBy - 32);
			ulong saveDroppedDigits = (ulong)(saveDroppedDigitsBI >> downby);


			////////  Shrink result to wanted Precision  ////////
			val >>= oversidedBy;


			////////  Detect a round-ups  ////////
			if ((saveDroppedDigits == 0) && (val * val > number))
			{
				val--;
			}

			////////// Error Detection ////////
			//// I believe the above has no errors but to guarantee the following can be added.
			//// If an error is found, please report it.
			//BigInteger tmp = val * val;
			//if (tmp > x)
			//{
			//    Console.WriteLine($"Missed  , {ToolsForOther.ToBinaryString(saveDroppedDigitsBI, oversidedBy)}, {oversidedBy}, {size}, {wantedPrecision}, {saveDroppedDigitsBI.GetBitLength()}");
			//    if (saveDroppedDigitsBI.GetBitLength() >= 6)
			//        Console.WriteLine($"val^2 ({tmp}) < x({x})  off%:{((double)(tmp)) / (double)x}");
			//    //throw new Exception("Sqrt function had internal error - value too high");
			//}
			//if ((tmp + 2 * val + 1) <= x)
			//{
			//    Console.WriteLine($"(val+1)^2({((val + 1) * (val + 1))}) >= x({x})");
			//    //throw new Exception("Sqrt function had internal error - value too low");
			//}

			return val;
		}
	}
}
