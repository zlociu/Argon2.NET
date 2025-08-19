//using Argon2;
//using System.Diagnostics;
//using System.Runtime.Intrinsics;
//using System.Runtime.Intrinsics.X86;

//public class BlamkaRoundOpt_SSE
//{
//    private static byte _MM_SHUFFLE(byte x, byte y, byte z, byte w)
//    {
//        return (byte)((z << 6) | (y << 4) | (x << 2) | w);
//    }

//    private static Vector128<byte> R16()
//    {
//        return Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
//    }

//    private static Vector128<byte> R24()
//    {
//        return Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
//    }

//    private static Vector128 MmRotiEpi64(Vector128<long> x, byte c)
//    {
//        return (-(c) == 32)
//        ? Ssse3.Shuffle(x.AsInt32(), _MM_SHUFFLE(2, 3, 0, 1))
//        : (-(c) == 24)
//            ? Ssse3.Shuffle(x.AsByte(), R24())
//            : (-(c) == 16)
//                ? Ssse3.Shuffle(x.AsByte(), R16())
//                : (-(c) == 63)
//                    ? Ssse3.Xor(Ssse3.ShiftRightLogical(x, -c), Ssse3.Add(x, x))
//                    : Ssse3.Xor(Ssse3.ShiftRightLogical(x, -c), Ssse3.ShiftLeftLogical(x, 64 - (-c)));
//    }



//    static BLAKE2_INLINE __m128i fBlaMka(__m128i x, __m128i y)
//    {
//        const __m128i z = _mm_mul_epu32(x, y);
//        return _mm_add_epi64(_mm_add_epi64(x, y), _mm_add_epi64(z, z));
//    }

//#define G1(A0, B0, C0, D0, A1, B1, C1, D1)                                     \
//		do
//{                                                                       \
//        A0 = fBlaMka(A0, B0);                                                  \
//        A1 = fBlaMka(A1, B1);                                                  \
//                                                                               \
//        D0 = _mm_xor_si128(D0, A0);                                            \
//        D1 = _mm_xor_si128(D1, A1);                                            \
//                                                                               \
//        D0 = MmRotiEpi64(D0, -32);                                          \
//        D1 = MmRotiEpi64(D1, -32);                                          \
//                                                                               \
//        C0 = fBlaMka(C0, D0);                                                  \
//        C1 = fBlaMka(C1, D1);                                                  \
//                                                                               \
//        B0 = _mm_xor_si128(B0, C0);                                            \
//        B1 = _mm_xor_si128(B1, C1);                                            \
//                                                                               \
//        B0 = MmRotiEpi64(B0, -24);                                          \
//        B1 = MmRotiEpi64(B1, -24);                                          \
//    } while ((void)0, 0)

//#define G2(A0, B0, C0, D0, A1, B1, C1, D1)                                     \
//    do
//{                                                                       \
//        A0 = fBlaMka(A0, B0);                                                  \
//        A1 = fBlaMka(A1, B1);                                                  \
//                                                                               \
//        D0 = _mm_xor_si128(D0, A0);                                            \
//        D1 = _mm_xor_si128(D1, A1);                                            \
//                                                                               \
//        D0 = MmRotiEpi64(D0, -16);                                          \
//        D1 = MmRotiEpi64(D1, -16);                                          \
//                                                                               \
//        C0 = fBlaMka(C0, D0);                                                  \
//        C1 = fBlaMka(C1, D1);                                                  \
//                                                                               \
//        B0 = _mm_xor_si128(B0, C0);                                            \
//        B1 = _mm_xor_si128(B1, C1);                                            \
//                                                                               \
//        B0 = MmRotiEpi64(B0, -63);                                          \
//        B1 = MmRotiEpi64(B1, -63);                                          \
//    } while ((void)0, 0)

//#if defined(__SSSE3__)
//#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                            \
//    do {                                                                       \
//        __m128i t0 = _mm_alignr_epi8(B1, B0, 8);                               \
//        __m128i t1 = _mm_alignr_epi8(B0, B1, 8);                               \
//        B0 = t0;                                                               \
//        B1 = t1;                                                               \
//                                                                               \
//        t0 = C0;                                                               \
//        C0 = C1;                                                               \
//        C1 = t0;                                                               \
//                                                                               \
//        t0 = _mm_alignr_epi8(D1, D0, 8);                                       \
//        t1 = _mm_alignr_epi8(D0, D1, 8);                                       \
//        D0 = t1;                                                               \
//        D1 = t0;                                                               \
//    } while ((void)0, 0)

//#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                          \
//    do {                                                                       \
//        __m128i t0 = _mm_alignr_epi8(B0, B1, 8);                               \
//        __m128i t1 = _mm_alignr_epi8(B1, B0, 8);                               \
//        B0 = t0;                                                               \
//        B1 = t1;                                                               \
//                                                                               \
//        t0 = C0;                                                               \
//        C0 = C1;                                                               \
//        C1 = t0;                                                               \
//                                                                               \
//        t0 = _mm_alignr_epi8(D0, D1, 8);                                       \
//        t1 = _mm_alignr_epi8(D1, D0, 8);                                       \
//        D0 = t1;                                                               \
//        D1 = t0;                                                               \
//    } while ((void)0, 0)
//#else /* SSE2 */
//#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                            \
//    do
//{                                                                       \
//        __m128i t0 = D0;                                                       \
//        __m128i t1 = B0;                                                       \
//        D0 = C0;                                                               \
//        C0 = C1;                                                               \
//        C1 = D0;                                                               \
//        D0 = _mm_unpackhi_epi64(D1, _mm_unpacklo_epi64(t0, t0));               \
//        D1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(D1, D1));               \
//        B0 = _mm_unpackhi_epi64(B0, _mm_unpacklo_epi64(B1, B1));               \
//        B1 = _mm_unpackhi_epi64(B1, _mm_unpacklo_epi64(t1, t1));               \
//    } while ((void)0, 0)

//#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                          \
//    do
//{                                                                       \
//        __m128i t0, t1;                                                        \
//        t0 = C0;                                                               \
//        C0 = C1;                                                               \
//        C1 = t0;                                                               \
//        t0 = B0;                                                               \
//        t1 = D0;                                                               \
//        B0 = _mm_unpackhi_epi64(B1, _mm_unpacklo_epi64(B0, B0));               \
//        B1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(B1, B1));               \
//        D0 = _mm_unpackhi_epi64(D0, _mm_unpacklo_epi64(D1, D1));               \
//        D1 = _mm_unpackhi_epi64(D1, _mm_unpacklo_epi64(t1, t1));               \
//    } while ((void)0, 0)
//#endif

//#define BLAKE2_ROUND(A0, A1, B0, B1, C0, C1, D0, D1)                           \
//    do
//{                                                                       \
//        G1(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
//        G2(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
//                                                                               \
//        DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);                           \
//                                                                               \
//        G1(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
//        G2(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
//                                                                               \
//        UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);                         \
//    } while ((void)0, 0)

//    public static void BLAKE2_ROUND_1(
//        ref Vector512<ulong> A0,
//        ref Vector512<ulong> B0,
//        ref Vector512<ulong> C0,
//        ref Vector512<ulong> D0,
//        ref Vector512<ulong> A1,
//        ref Vector512<ulong> B1,
//        ref Vector512<ulong> C1,
//        ref Vector512<ulong> D1)
//{

//}

//public static void BLAKE2_ROUND_2(
//    ref Vector512<ulong> A0,
//    ref Vector512<ulong> B0,
//    ref Vector512<ulong> C0,
//    ref Vector512<ulong> D0,
//    ref Vector512<ulong> A1,
//    ref Vector512<ulong> B1,
//    ref Vector512<ulong> C1,
//    ref Vector512<ulong> D1)
//{
//    G1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);
//    G2(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);

//    DIAGONALIZE(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);

//    G1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);
//    G2(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);

//    DIAGONALIZE(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);
//}
//}

//public class BlamkaRoundOpt_AVX2
//{

//}

//public class BlamkaRoundOpt_AVX512
//{

//}




//static Vector512<ulong> MulAdd(Vector512<ulong> x, Vector512<ulong> y)
//{
//    Vector512<ulong> z = Vector512.Multiply(x, y);
//    return Vector512.Add(Vector512.Add(x, y), Vector512.Add(z, z));
//}

//private void G1(
//    ref Vector512<ulong> A0,
//    ref Vector512<ulong> B0,
//    ref Vector512<ulong> C0,
//    ref Vector512<ulong> D0,
//    ref Vector512<ulong> A1,
//    ref Vector512<ulong> B1,
//    ref Vector512<ulong> C1,
//    ref Vector512<ulong> D1)
//{
//    A0 = MulAdd(A0, B0);
//    A1 = MulAdd(A1, B1);

//    D0 = Vector512.Xor(D0, A0);
//    D1 = Vector512.Xor(D1, A1);

//    D0 = Avx512F.RotateRight(D0, 32);
//    D1 = Avx512F.RotateRight(D1, 32);

//    C0 = MulAdd(C0, D0);
//    C1 = MulAdd(C1, D1);

//    B0 = Vector512.Xor(B0, C0);
//    B1 = Vector512.Xor(B1, C1);

//    B0 = Avx512F.RotateRight(B0, 24);
//    B1 = Avx512F.RotateRight(B1, 24);
//}

//private void G2(
//    ref Vector512<ulong> A0,
//    ref Vector512<ulong> B0,
//    ref Vector512<ulong> C0,
//    ref Vector512<ulong> D0,
//    ref Vector512<ulong> A1,
//    ref Vector512<ulong> B1,
//    ref Vector512<ulong> C1,
//    ref Vector512<ulong> D1)
//{

//    A0 = MulAdd(A0, B0);
//    A1 = MulAdd(A1, B1);

//    D0 = Vector512.Xor(D0, A0);
//    D1 = Vector512.Xor(D1, A1);

//    D0 = Avx512F.RotateRight(D0, 16);
//    D1 = Avx512F.RotateRight(D1, 16);

//    C0 = MulAdd(C0, D0);
//    C1 = MulAdd(C1, D1);

//    B0 = Vector512.Xor(B0, C0);
//    B1 = Vector512.Xor(B1, C1);

//    B0 = Avx512F.RotateRight(B0, 63);
//    B1 = Avx512F.RotateRight(B1, 63);
//}

//#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) 
//do
//{
//    B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1));
//    B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1));

//    C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2));
//    C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2));

//    D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3));
//    D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3));
//} while ((void)0, 0)

//    #define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) 
//        do
//{
//    B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3));
//    B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3));

//    C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2));
//    C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2));

//    D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1));
//    D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1));
//} while ((void)0, 0)

//    #define BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1) 
//        do
//{
//    G1(A0, B0, C0, D0, A1, B1, C1, D1);
//    G2(A0, B0, C0, D0, A1, B1, C1, D1);

//    DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);

//    G1(A0, B0, C0, D0, A1, B1, C1, D1);
//    G2(A0, B0, C0, D0, A1, B1, C1, D1);

//    UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);
//} while ((void)0, 0)

//    #define SWAP_HALVES(A0, A1) 
//        do
//{
//    __m512i t0, t1;
//    t0 = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(1, 0, 1, 0));
//    t1 = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(3, 2, 3, 2));
//    A0 = t0;
//    A1 = t1;
//} while ((void)0, 0)

//    #define SWAP_QUARTERS(A0, A1) 
//        do
//{
//    SWAP_HALVES(A0, A1);
//    A0 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A0);
//    A1 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A1);
//} while ((void)0, 0)

//    #define UNSWAP_QUARTERS(A0, A1) 
//        do
//{
//    A0 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A0);
//    A1 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A1);
//    SWAP_HALVES(A0, A1);
//} while ((void)0, 0)

//    #define BLAKE2_ROUND_1(A0, C0, B0, D0, A1, C1, B1, D1) 
//        do
//{
//    SWAP_HALVES(A0, B0);
//    SWAP_HALVES(C0, D0);
//    SWAP_HALVES(A1, B1);
//    SWAP_HALVES(C1, D1);
//    BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1);
//    SWAP_HALVES(A0, B0);
//    SWAP_HALVES(C0, D0);
//    SWAP_HALVES(A1, B1);
//    SWAP_HALVES(C1, D1);
//} while ((void)0, 0)

//    #define BLAKE2_ROUND_2(A0, A1, B0, B1, C0, C1, D0, D1) 
//        do
//{
//    SWAP_QUARTERS(A0, A1);
//    SWAP_QUARTERS(B0, B1);
//    SWAP_QUARTERS(C0, C1);
//    SWAP_QUARTERS(D0, D1);
//    BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1);
//    UNSWAP_QUARTERS(A0, A1);
//    UNSWAP_QUARTERS(B0, B1);
//    UNSWAP_QUARTERS(C0, C1);
//    UNSWAP_QUARTERS(D0, D1);
//} while ((void)0, 0)
//}
