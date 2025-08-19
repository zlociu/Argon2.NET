using System;

namespace Argon2.Blake2;

public class Blake2b// : IBlake2b
{
    public ulong[] h = new ulong[8];
    public ulong[] t = new ulong[2];
    public ulong[] f = new ulong[2];
    public byte[] buf = new byte[Blake2Consts.BLAKE2B_BLOCKBYTES];
    public uint buflen;
    public uint outlen;
    public byte last_node;

    private static readonly ulong[] blake2b_IV = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    private static readonly int[][] blake2b_sigma = {
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    };

    private void blake2b_set_lastnode() {
        this.f[1] = ulong.MaxValue;
    }

    private void blake2b_set_lastblock() {
        if (this.last_node > 0) {
            blake2b_set_lastnode();
        }
    
        this.f[0] = ulong.MaxValue;
    }

    private void blake2b_increment_counter(ulong inc)
    {
        this.t[0] += inc;
        this.t[1] += ((this.t[0] < inc) ? 1UL : 0UL);
    }

    private void blake2b_invalidate_state() {
        blake2b_set_lastblock(); /* invalidate for further use */
    }

    private void Blake2bInit() {
        Array.Copy(blake2b_IV, this.h, 8);
    }
    
    private int Blake2bInitParam(in Blake2bParam p)
    {
        if (p is null) {
            return -1;
        }

        Blake2bInit();
        /* IV XOR Parameter Block */

        var serializedParams = p.SerializeToArray();

        for (int i = 0; i < 8; ++i) {
            this.h[i] ^= serializedParams[i];
        }
        
        this.outlen = p.digest_length;
        return 0;
    }

    /* Sequential blake2b initialization */
    public int Blake2bInit(long outlen)
    {
        Blake2bParam P = new();

        if ((outlen == 0) || (outlen > Blake2Consts.BLAKE2B_OUTBYTES)) {
            blake2b_invalidate_state();
            return -1;
        }

        /* Setup Parameter Block for unkeyed BLAKE2 */
        P.digest_length = (byte)outlen;
        P.key_length = 0;
        P.fanout = 1;
        P.depth = 1;
        P.leaf_length = 0;
        P.node_offset = 0;
        P.node_depth = 0;
        P.inner_length = 0;

        return Blake2bInitParam(P);
    }

    public int Blake2bInitKey(long outlen, in byte[] key) {
        Blake2bParam P = new();

        if ((outlen == 0) || (outlen > Blake2Consts.BLAKE2B_OUTBYTES)) {
            this.blake2b_invalidate_state();
            return -1;
        }
        
        if ((key is null) || (key.Length == 0) || (key.Length > Blake2Consts.BLAKE2B_KEYBYTES)) {
            this.blake2b_invalidate_state();
            return -1;
        }

        /* Setup Parameter Block for keyed BLAKE2 */
        P.digest_length = (byte)outlen;
        P.key_length = (byte)key.Length;
        P.fanout = 1;
        P.depth = 1;
        P.leaf_length = 0;
        P.node_offset = 0;
        P.node_depth = 0;
        P.inner_length = 0;

        if (this.Blake2bInitParam(P) < 0) {
            this.blake2b_invalidate_state();
            return -1;
        }
        
        {
            byte[] block = new byte[Blake2Consts.BLAKE2B_BLOCKBYTES];
            key.CopyTo(block, 0);
            this.Blake2bUpdate(block);
        }
        return 0;
    }

    private void Blake2bCompress(ReadOnlySpan<byte> span) {
        ulong[] m = new ulong[16];
        ulong[] v = new ulong[16];
        int i;
        int r;

        for (i = 0; i < 16; ++i) {
            m[i] = Blake2Impl.load64(span.Slice(i * sizeof(ulong), sizeof(ulong)));
        }

        for (i = 0; i < 8; ++i) {
            v[i] = this.h[i];
        }

        v[8] = blake2b_IV[0];
        v[9] = blake2b_IV[1];
        v[10] = blake2b_IV[2];
        v[11] = blake2b_IV[3];
        v[12] = blake2b_IV[4] ^ this.t[0];
        v[13] = blake2b_IV[5] ^ this.t[1];
        v[14] = blake2b_IV[6] ^ this.f[0];
        v[15] = blake2b_IV[7] ^ this.f[1];

        void G(int r, ulong i, ref ulong a, ref ulong b, ref ulong c, ref ulong d)                                                   
        {                                                                      
            a = a + b + m[blake2b_sigma[r][2 * i + 0]];                           
            d = BitOperations.RotateRight(d ^ a, 32);
            c += d;                                                      
            b = BitOperations.RotateRight(b ^ c, 24);                                                
            a = a + b + m[blake2b_sigma[r][2 * i + 1]];                           
            d = BitOperations.RotateRight(d ^ a, 16);                                                
            c += d;                                                          
            b = BitOperations.RotateRight(b ^ c, 63);                                                
        }

        void Round(int r)
        {
            G(r, 0, ref v[0], ref v[4], ref v[8], ref v[12]);
            G(r, 1, ref v[1], ref v[5], ref v[9], ref v[13]);
            G(r, 2, ref v[2], ref v[6], ref v[10], ref v[14]);
            G(r, 3, ref v[3], ref v[7], ref v[11], ref v[15]);
            G(r, 4, ref v[0], ref v[5], ref v[10], ref v[15]);
            G(r, 5, ref v[1], ref v[6], ref v[11], ref v[12]);
            G(r, 6, ref v[2], ref v[7], ref v[8], ref v[13]);
            G(r, 7, ref v[3], ref v[4], ref v[9], ref v[14]);
        }

        for (r = 0; r < 12; ++r) Round(r);

        for (i = 0; i < 8; ++i)
            this.h[i] = this.h[i] ^ v[i] ^ v[i + 8];
    }

    public  int Blake2bUpdate(in byte[] _in)
    {
        if (_in is null) return -1;

        if (_in.Length == 0) return 0;

        /* Is this a reused state? */
        if (this.f[0] != 0) return -1;
        
        int inIdx = 0;
        int inLength = _in.Length;
        
        if (this.buflen + inLength > Blake2Consts.BLAKE2B_BLOCKBYTES) {
            /* Complete current block */
            int left = (int)this.buflen;
            int fill = Blake2Consts.BLAKE2B_BLOCKBYTES - left;
            Array.Copy(_in, inIdx, this.buf, left, fill);
            blake2b_increment_counter(Blake2Consts.BLAKE2B_BLOCKBYTES);
            Blake2bCompress(this.buf);
            this.buflen = 0;
            inLength -= fill;
            inIdx += fill;
            /* Avoid buffer copies when possible */
            while (inLength > Blake2Consts.BLAKE2B_BLOCKBYTES) {
                blake2b_increment_counter(Blake2Consts.BLAKE2B_BLOCKBYTES);
                Blake2bCompress(_in.AsSpan(inIdx, Blake2Consts.BLAKE2B_BLOCKBYTES));
                inLength -= Blake2Consts.BLAKE2B_BLOCKBYTES;
                inIdx += Blake2Consts.BLAKE2B_BLOCKBYTES;
            }
        }
        
        Array.Copy(_in, inIdx, this.buf, this.buflen, inLength);
        this.buflen += (uint)inLength;
        
        return 0;
    }

    public int Blake2bFinal(byte[] _out, long outlen) {
        byte[] buffer = new byte[Blake2Consts.BLAKE2B_OUTBYTES];
        uint i;

        /* Sanity checks */
        if (_out is null || outlen < this.outlen) {
            return -1;
        }

        /* Is this a reused state? */
        if (this.f[0] != 0) {
            return -1;
        }

        this.blake2b_increment_counter(this.buflen);
        this.blake2b_set_lastblock();

        Array.Fill<byte>(this.buf, 0, (int)this.buflen, Blake2Consts.BLAKE2B_BLOCKBYTES - (int)this.buflen);
        this.Blake2bCompress(this.buf);

        for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
            var bytes = Blake2Impl.store64(this.h[i]);
            Array.Copy(bytes, 0, buffer, sizeof(ulong) * i, sizeof(ulong)); 
        }

        Array.Copy(buffer, _out, this.outlen);
        return 0;
    }
    
    private static int blake2b(byte[] _out, long outlen, in byte[] _in, long inlen, in byte[] key, long keylen)
    {
        Blake2b state = new();

        int ret = -1;

        /* Verify parameters */
        if (_in is null && inlen > 0) {
            return ret;
        }

        if (_out is null || outlen == 0 || outlen > Blake2Consts.BLAKE2B_OUTBYTES) {
            return ret;
        }

        if ((key is null && keylen > 0) || keylen > Blake2Consts.BLAKE2B_KEYBYTES) {
            return ret;
        }

        if (keylen > 0) {
            if (state.Blake2bInitKey(outlen, key) < 0) return ret;
        } else {
            if (state.Blake2bInit(outlen) < 0) return ret;
        }

        if (state.Blake2bUpdate(_in) < 0)
            return ret;

        return state.Blake2bFinal(_out, outlen);
    }

    /* Argon2 Team - Begin Code */
    public static int Blake2bLong(byte[] _out, long outlen, in byte[] _in)
    {
        Blake2b blake_state = new();
        int ret = -1;

        if (outlen > uint.MaxValue) {
            return ret;
        }

        /* Ensure little-endian byte order! */
        byte[] outlen_bytes = Blake2Impl.store32((uint)outlen);

        if (outlen <= Blake2Consts.BLAKE2B_OUTBYTES)
        {
            if (blake_state.Blake2bInit(outlen) < 0) return -1;
            if (blake_state.Blake2bUpdate(outlen_bytes) < 0) return -1;
            if (blake_state.Blake2bUpdate(_in) < 0) return -1;
            if (blake_state.Blake2bFinal(_out, outlen) < 0) return -1;
        }
        else
        {
            int outIdx = 0;

            uint toproduce;
            byte[] out_buffer = new byte[Blake2Consts.BLAKE2B_OUTBYTES];
            byte[] in_buffer = new byte[Blake2Consts.BLAKE2B_OUTBYTES];
            if (blake_state.Blake2bInit(Blake2Consts.BLAKE2B_OUTBYTES) < 0) return -1;
            if (blake_state.Blake2bUpdate(outlen_bytes) < 0) return -1;
            if (blake_state.Blake2bUpdate(_in) < 0) return -1;
            if (blake_state.Blake2bFinal(out_buffer, Blake2Consts.BLAKE2B_OUTBYTES) < 0) return -1;

            Array.Copy(out_buffer, 0, _out, outIdx, Blake2Consts.BLAKE2B_OUTBYTES / 2);

            outIdx += Blake2Consts.BLAKE2B_OUTBYTES / 2;
            
            toproduce = (uint)outlen - Blake2Consts.BLAKE2B_OUTBYTES / 2;

            while (toproduce > Blake2Consts.BLAKE2B_OUTBYTES)
            {
                Array.Copy(out_buffer, in_buffer, Blake2Consts.BLAKE2B_OUTBYTES);
                
                if (blake2b(
                    out_buffer,
                    Blake2Consts.BLAKE2B_OUTBYTES,
                    in_buffer,
                    Blake2Consts.BLAKE2B_OUTBYTES,
                    null,
                    0) < 0) return -1;

                Array.Copy(out_buffer, 0, _out, outIdx, Blake2Consts.BLAKE2B_OUTBYTES/ 2);
                
                outIdx += Blake2Consts.BLAKE2B_OUTBYTES / 2;
                toproduce -= Blake2Consts.BLAKE2B_OUTBYTES / 2;
            }

            Array.Copy(out_buffer, in_buffer, Blake2Consts.BLAKE2B_OUTBYTES);
            
            if (blake2b(out_buffer, toproduce, in_buffer, Blake2Consts.BLAKE2B_OUTBYTES, null, 0) < 0) return -1;

            Array.Copy(out_buffer, 0, _out, outIdx, toproduce);
        }

        return 0;
    }
}
