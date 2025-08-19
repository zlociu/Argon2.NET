namespace Argon2.Blake2;

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/* Argon2 Team - Begin Code */
/*
   Not an exhaustive list, but should cover the majority of modern platforms
   Additionally, the code will always be correct---this is only a performance
   tweak.
*/
public class Blake2Impl
{
    public static ulong load64(ReadOnlySpan<byte> src) {
        return BitConverter.ToUInt64(src);
    }

    public static byte[] store32(uint w)
    {
        return BitConverter.GetBytes(w);
    }

    public static byte[] store64(ulong w)
    {
        return BitConverter.GetBytes(w);
    }
}
public static class BitOperations
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateLeft(uint number, int bits)
    {
        return (number << bits) | (number >> (32 - bits));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateLeft(ulong number, int bits)
    {
        return (number << bits) | (number >> (64 - bits));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateRight(uint number, int bits)
    {
        return (number >> bits) | (number << (32 - bits));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateRight(ulong number, int bits)
    {
        return (number >> bits) | (number << (64 - bits));
    }
}

