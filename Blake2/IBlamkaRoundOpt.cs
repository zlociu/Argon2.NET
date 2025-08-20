using System.Numerics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace Argon2.Core;

public class BlamkaOpt
{
    private static Vector256<ulong> rotr32(Vector256<ulong> x) => Avx2.Shuffle(x.AsUInt32(), 0b_10_11_00_01).AsUInt64();
    private static Vector256<ulong> rotr24(Vector256<ulong> x) => Avx2.Shuffle(x.AsByte(), Vector256.Create<byte>([3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10])).AsUInt64();
    private static Vector256<ulong> rotr16(Vector256<ulong> x) => Avx2.Shuffle(x.AsByte(), Vector256.Create<byte>([2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9])).AsUInt64();
    private static Vector256<ulong> rotr63(Vector256<ulong> x) => Avx2.Xor(Avx2.ShiftRightLogical(x, 63), Avx2.Add(x, x));

    private static void G1(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        Vector256<ulong> ml = Avx2.Multiply(A0.AsUInt32(), B0.AsUInt32());

        ml = Avx2.Add(ml, ml);
        A0 = Avx2.Add(A0, Avx2.Add(B0, ml));
        D0 = Avx2.Xor(D0, A0);
        D0 = rotr32(D0);

        ml = Avx2.Multiply(C0.AsUInt32(), D0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C0 = Avx2.Add(C0, Avx2.Add(D0, ml));
        B0 = Avx2.Xor(B0, C0);
        B0 = rotr24(B0);

        ml = Avx2.Multiply(A1.AsUInt32(), B1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A1 = Avx2.Add(A1, Avx2.Add(B1, ml));
        D1 = Avx2.Xor(D1, A1);
        D1 = rotr32(D1);

        ml = Avx2.Multiply(C1.AsUInt32(), D1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C1 = Avx2.Add(C1, Avx2.Add(D1, ml));
        B1 = Avx2.Xor(B1, C1);
        B1 = rotr24(B1);
    }

    private static void G2(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        Vector256<ulong> ml = Avx2.Multiply(A0.AsUInt32(), B0.AsUInt32());

        ml = Avx2.Add(ml, ml);
        A0 = Avx2.Add(A0, Avx2.Add(B0, ml));
        D0 = Avx2.Xor(D0, A0);
        D0 = rotr16(D0);

        ml = Avx2.Multiply(C0.AsUInt32(), D0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C0 = Avx2.Add(C0, Avx2.Add(D0, ml));
        B0 = Avx2.Xor(B0, C0);
        B0 = rotr63(B0);

        ml = Avx2.Multiply(A1.AsUInt32(), B1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A1 = Avx2.Add(A1, Avx2.Add(B1, ml));
        D1 = Avx2.Xor(D1, A1);
        D1 = rotr16(D1);

        ml = Avx2.Multiply(C1.AsUInt32(), D1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C1 = Avx2.Add(C1, Avx2.Add(D1, ml));
        B1 = Avx2.Xor(B1, C1);
        B1 = rotr63(B1);
    }

    private static void Diagonalize1(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D1)
    {
        B0 = Avx2.Permute4x64(B0, 0b_00_11_10_01);
        C0 = Avx2.Permute4x64(C0, 0b_01_00_11_10);
        D0 = Avx2.Permute4x64(D0, 0b_10_01_00_11);

        B1 = Avx2.Permute4x64(B1, 0b_00_11_10_01);
        C1 = Avx2.Permute4x64(C1, 0b_01_00_11_10);
        D1 = Avx2.Permute4x64(D1, 0b_10_01_00_11);
    }

    private static void Diagonalize2(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        Vector256<ulong> tmp1 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0xCC).AsUInt64();
        Vector256<ulong> tmp2 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0x33).AsUInt64();

        B1 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        B0 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);

        tmp1 = C0;
        C0 = C1;
        C1 = tmp1;

        tmp1 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0xCC).AsUInt64();
        tmp2 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0x33).AsUInt64();

        D0 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        D1 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);
    }

    private static void Undiagonalize1(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D1)
    {
        B0 = Avx2.Permute4x64(B0, 0b_10_01_00_11);
        C0 = Avx2.Permute4x64(C0, 0b_01_00_11_10);
        D0 = Avx2.Permute4x64(D0, 0b_00_11_10_01);

        B1 = Avx2.Permute4x64(B1, 0b_10_01_00_11);
        C1 = Avx2.Permute4x64(C1, 0b_01_00_11_10);
        D1 = Avx2.Permute4x64(D1, 0b_00_11_10_01);
    }

    private static void Undiagonalize2(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        Vector256<ulong> tmp1 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0xCC).AsUInt64();
        Vector256<ulong> tmp2 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0x33).AsUInt64();

        B0 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        B1 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);

        tmp1 = C0;
        C0 = C1;
        C1 = tmp1;

        tmp1 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0x33).AsUInt64();
        tmp2 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0xCC).AsUInt64();

        D0 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        D1 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);
    }

    public static void Blake2Round1(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        G1(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);

        G1(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);
    }

    public static void Blake2Round2(
        ref Vector256<ulong> A0,
        ref Vector256<ulong> A1,
        ref Vector256<ulong> B0,
        ref Vector256<ulong> B1,
        ref Vector256<ulong> C0,
        ref Vector256<ulong> C1,
        ref Vector256<ulong> D0,
        ref Vector256<ulong> D1)
    {
        G1(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        G1(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
    }
}
