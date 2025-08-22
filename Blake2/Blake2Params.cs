namespace Argon2.Blake2;


public class Blake2Consts {
    public const int BLAKE2B_BLOCKBYTES = 128;
    public const int BLAKE2B_OUTBYTES = 64;
    public const int BLAKE2B_KEYBYTES = 64;
    public const int BLAKE2B_SALTBYTES = 16;
    public const int BLAKE2B_PERSONALBYTES = 16;
};

public class Blake2bParam
{
    internal byte digest_length;                                              //  1 
    internal byte key_length;                                                 //  2 
    internal byte fanout;                                                     //  3 
    internal byte depth;                                                      //  4 
    internal uint leaf_length;                                                //  8 
    internal ulong node_offset;                                               //  16
    internal byte node_depth;                                                 //  17
    internal byte inner_length;                                               //  18
    internal byte[] reserved = new byte[14];                                  //  32
    internal byte[] salt = new byte[Blake2Consts.BLAKE2B_SALTBYTES];            //  48
    internal byte[] personal = new byte[Blake2Consts.BLAKE2B_PERSONALBYTES];    //  64

    public ulong[] SerializeToArray()
    {
        var result = new ulong[8];
        
        if (BitConverter.IsLittleEndian)
        {
            result[0] =
                ((ulong)this.digest_length) |
                ((ulong)this.key_length << 8) |
                ((ulong)this.fanout << 16) |
                ((ulong)this.depth << 24) |
                ((ulong)leaf_length << 32);

            result[1] = this.node_offset;
            result[2] = ((ulong)this.node_depth) | ((ulong)this.inner_length << 8);

            for (int i = 0; i < 6; i++)
            {
                result[2] = result[2] | ((ulong)reserved[i] << (16 + 8 * i));
            }

            for (int i = 0; i < 8; i++)
            {
                result[3] = result[3] | ((ulong)reserved[i + 6] << (8 * i));
            }
        }
        else
        {
            result[0] =
                ((ulong)this.digest_length << 56) |
                ((ulong)this.key_length << 48) |
                ((ulong)this.fanout << 40) |
                ((ulong)this.depth << 32) |
                leaf_length;
            result[1] = this.node_offset;
            result[2] = ((ulong)this.node_depth << 56) | ((ulong)this.inner_length << 48);

            for (int i = 0; i < 6; i++)
            {
                result[2] = result[2] | ((ulong)reserved[i] << (40 - 8 * i));
            }

            for (int i = 0; i < 8; i++)
            {
                result[3] = result[3] | ((ulong)reserved[i + 6] << (56 - 8 * i));
            }
        }

        var saltSpan = salt.AsSpan();
        var personalSpan = personal.AsSpan();

        result[4] = BitConverter.ToUInt64(saltSpan.Slice(0, 8));
        result[5] = BitConverter.ToUInt64(saltSpan.Slice(8, 8));
        result[6] = BitConverter.ToUInt64(personalSpan.Slice(0, 8));
        result[7] = BitConverter.ToUInt64(personalSpan.Slice(8,8));

        return result;
    }
}

public class Blake2bState
{
    public ulong[] h = new ulong[8];
    public ulong[] t = new ulong[2];
    public ulong[] f = new ulong[2];
    public byte[] buf = new byte[Blake2Consts.BLAKE2B_BLOCKBYTES];
    public uint buflen;
    public uint outlen;
    public byte lastNode;
}
