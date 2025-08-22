using Argon2.Blake2;
using Argon2.Enums;
using System.Runtime.Intrinsics.X86;

namespace Argon2.Core;

/// <summary>
/// Argon2 instance: memory pointer, number of passes, amount of memory, type, and derived values. <para/>
/// Used to evaluate the number and location of blocks to construct in each thread
/// </summary>
internal class Argon2Instance
{
    public Block[] memory;          /* Memory pointer */
    public Argon2Version version;
    public uint passes;        /* Number of passes */
    public uint memory_blocks; /* Number of blocks in memory */
    public uint segment_length;
    public uint lane_length;
    public uint lanes;
    public uint threads;
    public Argon2Type type;
    public int print_internals; /* whether to print the memory blocks */
    public Argon2Context context_ptr; /* points back to original context */
    public Argon2Instance(Argon2Context context, Argon2Type type)
    {
        uint memory_blocks, segment_length;

        // Minimum memory_blocks = 8L blocks, where L is the number of lanes //
        memory_blocks = context.MCost;

        if (memory_blocks < 2 * Consts.ARGON2_SYNC_POINTS * context.Lanes)
            memory_blocks = 2 * Consts.ARGON2_SYNC_POINTS * context.Lanes;

        segment_length = memory_blocks / (context.Lanes * Consts.ARGON2_SYNC_POINTS);
        // Ensure that all segments have equal length //
        memory_blocks = segment_length * (context.Lanes * Consts.ARGON2_SYNC_POINTS);

        this.version = context.Version;
        this.memory = [];
        this.passes = context.TCost;
        this.memory_blocks = memory_blocks;
        this.segment_length = segment_length;
        this.lane_length = segment_length * Consts.ARGON2_SYNC_POINTS;
        this.lanes = context.Lanes;
        this.threads = context.Threads;
        this.type = type;
        this.context_ptr = context;

        if (this.threads > this.lanes)
            this.threads = this.lanes;
    }

    /// <summary>
    /// XORing the last block of each lane, hashing it, making the tag.
    /// </summary>
    public void Finish()
    {
        Block blockhash = new(this.memory[this.lane_length - 1]);

        /* XOR the last blocks */
        for (uint l = 1; l < this.lanes; ++l)
        {
            uint last_Blockin_lane = l * this.lane_length + (this.lane_length - 1);
            blockhash.XorBlock(this.memory[last_Blockin_lane]);
        }

        /* Hash the result */
        {
            byte[] blockhash_bytes = blockhash.StoreBlock();
            Blake2b.Blake2bLong(this.context_ptr.Out, this.context_ptr.Out.LongLength, blockhash_bytes);
        }
    }

    /* Single-threaded version for p=1 case */
    private Argon2_ErrorCodes FillMemoryBlocksST()
    {
        uint r, s, l;

        for (r = 0; r < this.passes; ++r)
        {
            for (s = 0; s < Consts.ARGON2_SYNC_POINTS; ++s)
            {
                for (l = 0; l < this.lanes; ++l)
                {
                    Argon2Position position = new()
                    {
                        pass = r,
                        lane = l,
                        slice = (byte)s,
                        index = 0
                    };

                    if (Avx2.IsSupported)
                    {
                        Opt.FillSegment(this, position);
                    }
                    else
                    {
                        Ref.FillSegment(this, position);
                    }
                }
            }
        }
        return Argon2_ErrorCodes.ARGON2_OK;
    }

    /* Multi-threaded version for p > 1 case */
    private Argon2_ErrorCodes FillMemoryBlocksMT()
    {
        uint r, s;
        Argon2_ErrorCodes rc = Argon2_ErrorCodes.ARGON2_OK;

        /* 1. Allocating space for threads */
        for (r = 0; r < this.passes; ++r)
        {
            for (s = 0; s < Consts.ARGON2_SYNC_POINTS; ++s)
            {
                /* 2. Calling threads */
                var result = Parallel.For(0, this.lanes, (l) =>
                {
                    Argon2Position position;

                    /* 2.2 Create thread */
                    position.pass = r;
                    position.lane = (uint)l;
                    position.slice = (byte)s;
                    position.index = 0;

                    if (Avx2.IsSupported)
                    {
                        Opt.FillSegment(this, position);
                    }
                    else
                    {
                        Ref.FillSegment(this, position);
                    }
                });
            }
        }

        return rc;
    }

    public Argon2_ErrorCodes FillMemoryBlocks()
    {
        if (this.lanes == 0)
            return Argon2_ErrorCodes.ARGON2_INCORRECT_PARAMETER;

        return this.threads == 1
            ? this.FillMemoryBlocksST()
            : this.FillMemoryBlocksMT();
    }


    /// <summary>
    /// Function creates first 2 blocks per lane
    /// </summary>
    /// <param name="blockhash">Pointer to the pre-hashing digest</param>
    private void FillFirstBlocks(byte[] blockhash)
    {
        uint l;
        // Make the first and second block in each lane as G(H0||0||i) or G(H0||1||i)
        byte[] blockhash_bytes = new byte[Consts.ARGON2_BLOCK_SIZE];
        for (l = 0; l < this.lanes; ++l)
        {
            BitConverter.GetBytes(0).CopyTo(blockhash, Consts.ARGON2_PREHASH_DIGEST_LENGTH);
            BitConverter.GetBytes(l).CopyTo(blockhash, Consts.ARGON2_PREHASH_DIGEST_LENGTH + 4);

            Blake2b.Blake2bLong(blockhash_bytes, Consts.ARGON2_BLOCK_SIZE, blockhash);

            this.memory[l * this.lane_length + 0] = Block.LoadBlock(blockhash_bytes);

            BitConverter.GetBytes(1).CopyTo(blockhash, Consts.ARGON2_PREHASH_DIGEST_LENGTH);
            Blake2b.Blake2bLong(
                blockhash_bytes,
                Consts.ARGON2_BLOCK_SIZE,
                blockhash);

            this.memory[l * this.lane_length + 1] = Block.LoadBlock(blockhash_bytes);
        }
    }

    /// <summary>
    /// Function allocates memory, hashes the inputs with Blake, and creates first two blocks. <br/>
    /// Returns the pointer to the main memory with 2 blocks per lane initialized
    /// </summary>
    public void Initialize()
    {
        byte[] blockhash = new byte[Consts.ARGON2_PREHASH_SEED_LENGTH];

        /* 1. Memory allocation */
        this.memory = new Block[this.memory_blocks];

        /* 2. Initial hashing */
        /* H_0 + 8 extra bytes to produce the first blocks */
        /* byte blockhash[Consts.ARGON2_PREHASH_SEED_LENGTH]; */
        /* Hashing all inputs */
        this.InitialHash(blockhash);

        Array.Clear(
            blockhash,
            Consts.ARGON2_PREHASH_DIGEST_LENGTH,
            Consts.ARGON2_PREHASH_SEED_LENGTH - Consts.ARGON2_PREHASH_DIGEST_LENGTH);

        /* 3. Creating first blocks, we always have at least two blocks in a slice */
        this.FillFirstBlocks(blockhash);
    }

    /// <summary>
    /// Computes absolute position of reference block in the lane following a skewed
    /// distribution and using a pseudo-random value as input
    /// </summary>
    /// <param name="position">Pointer to the current position</param>
    /// <param name="pseudo_rand">32-bit pseudo-random value used to determine the position</param>
    /// <param name="same_lane">Indicates if the block will be taken from the current lane.</param>
    /// <returns></returns>
    public uint IndexAlpha(
        ref Argon2Position position,
        uint pseudo_rand,
        bool same_lane)
    {
        /*
            Pass 0:
                 This lane : all already finished segments plus already constructed
            blocks in this segment
                 Other lanes : all already finished segments
            Pass 1+:
                 This lane : (SYNC_POINTS - 1) last segments plus already constructed
            blocks in this segment
                 Other lanes : (SYNC_POINTS - 1) last segments
         */
        uint reference_area_size;
        ulong relative_position;
        uint start_position, absolute_position;

        if (0 == position.pass)
        {
            /* First pass */
            if (0 == position.slice)
            {
                /* First slice */
                reference_area_size = position.index - 1; /* all but the previous */
            }
            else
            {
                if (same_lane)
                {
                    /* The same lane => add current segment */
                    reference_area_size =
                        position.slice * this.segment_length +
                        position.index - 1;
                }
                else
                {
                    reference_area_size =
                        position.slice * this.segment_length - (position.index == 0u ? 1u : 0u);
                }
            }
        }
        else
        {
            /* Second pass */
            if (same_lane)
            {
                reference_area_size =
                    this.lane_length - this.segment_length + position.index - 1;
            }
            else
            {
                reference_area_size =
                    this.lane_length - this.segment_length - ((position.index == 0) ? 1u : 0u);
            }
        }

        /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
         * relative position */
        relative_position = pseudo_rand;
        relative_position = relative_position * relative_position >> 32;
        relative_position = reference_area_size - 1 -
                            (reference_area_size * relative_position >> 32);

        /* 1.2.5 Computing starting position */
        start_position = 0;

        if (0 != position.pass)
        {
            start_position = (position.slice == (Consts.ARGON2_SYNC_POINTS - 1U))
                ? 0U
                : (position.slice + 1U) * this.segment_length;
        }

        /* 1.2.6. Computing absolute position */
        absolute_position = (uint)((start_position + relative_position) % this.lane_length); /* absolute position */
        return absolute_position;
    }

    /// <summary>
    /// Hashes all the inputs into @a blockhash[PREHASH_DIGEST_LENGTH], clears password and secret if needed
    /// </summary>
    /// <param name="blockhash">Buffer for pre-hashing digest</param>
    /// <param name="context">Pointer to the Argon2 internal structure containing memory</param>
    /// <param name="type">Argon2 type</param>
    private void InitialHash(byte[] blockhash)
    {
        Blake2b blakeHash = new();
        byte[] value;
        if (blockhash is null)
            return;

        var context = this.context_ptr;

        blakeHash.Blake2bInit(Consts.ARGON2_PREHASH_DIGEST_LENGTH);

        value = BitConverter.GetBytes(context.Lanes);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes((uint)context.Out.Length);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes(context.MCost);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes(context.TCost);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes((uint)context.Version);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes((uint)type);
        blakeHash.Blake2bUpdate(value);

        value = BitConverter.GetBytes((uint)context.Pwd.Length);
        blakeHash.Blake2bUpdate(value);

        if (context.Pwd is not null && context.Pwd.Length > 0)
        {
            blakeHash.Blake2bUpdate(context.Pwd);

            if ((context.Flags & Consts.ARGON2_FLAG_CLEAR_PASSWORD) > 0)
                context.Pwd = [];
        }

        value = BitConverter.GetBytes((uint)context.Salt.Length);
        blakeHash.Blake2bUpdate(value);

        if (context.Salt is not null && context.Salt.Length > 0)
        {
            blakeHash.Blake2bUpdate(context.Salt);
        }

        value = BitConverter.GetBytes((uint)context.Secret.Length);
        blakeHash.Blake2bUpdate(value);

        if (context.Secret is not null && context.Secret.Length > 0)
        {
            blakeHash.Blake2bUpdate(context.Secret);

            if ((context.Flags & Consts.ARGON2_FLAG_CLEAR_SECRET) > 0)
                context.Secret = [];
        }

        value = BitConverter.GetBytes((uint)context.Ad.Length);
        blakeHash.Blake2bUpdate(value);

        if (context.Ad is not null && context.Ad.Length > 0)
        {
            blakeHash.Blake2bUpdate(context.Ad);
        }

        blakeHash.Blake2bFinal(blockhash, Consts.ARGON2_PREHASH_DIGEST_LENGTH);
    }
}
