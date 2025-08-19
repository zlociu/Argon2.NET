namespace Argon2.Core;

/// <summary>
/// Structure for the (1KB) memory block implemented as 128 64-bit words.
/// Memory blocks can be copied, XORed. Internal words can be accessed by [] (no bounds checking).
/// </summary>
internal class Block
{
    public ulong[] V { get; } = new ulong[Consts.ARGON2_QWORDS_IN_BLOCK];

    public Block() { }

    public Block(ulong value) : this()
    {
        Array.Fill(this.V, value);
    }

    public Block(ReadOnlySpan<ulong> span) : this()
    {
        if (span.Length != Consts.ARGON2_QWORDS_IN_BLOCK)
            throw new ArgumentException("span has wrong length", nameof(span));

        span.CopyTo(this.V);
    }

    public Block(Block src)
    {
        src.V.CopyTo(this.V, 0);
    }

    public void XorBlock(in Block src)
    {
        for (int i = 0; i < Consts.ARGON2_QWORDS_IN_BLOCK; ++i)
            this.V[i] ^= src.V[i];
    }

    public static Block LoadBlock(byte[] source)
    {
        Block dst = new();
        ReadOnlySpan<byte> span = source.AsSpan();

        for (int i = 0; i < Consts.ARGON2_QWORDS_IN_BLOCK; ++i)
        {
            dst.V[i] = BitConverter.ToUInt64(span.Slice(i * sizeof(ulong), 8));
        }

        return dst;
    }

    public byte[] StoreBlock()
    {
        byte[] output = new byte[Consts.ARGON2_BLOCK_SIZE];

        for (int i = 0; i < Consts.ARGON2_QWORDS_IN_BLOCK; ++i)
        {
            var bytes = BitConverter.GetBytes(this.V[i]);
            for (int k = 0; k < sizeof(ulong); k++)
            {
                output[i * sizeof(ulong) + k] = bytes[k];
            }
        }

        return output;
    }
}
