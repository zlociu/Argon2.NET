namespace Argon2;

using Argon2.Blake2;
using Argon2.Core;
using Argon2.Enums;

internal class Ref
{
    /// <summary>
    /// Function fills a new memory block and optionally XORs the old block over the new one.
    /// </summary>
    /// <param name="prev_block">Pointer to the previous block</param>
    /// <param name="ref_block">Pointer to the reference block</param>
    /// <param name="with_xor">Whether to XOR into the new block or just overwrite </param>
    /// <returns>the block to be constructed</returns>
    private static Block FillBlock(
        in Block prev_block,
        in Block ref_block,
        in Block next_block,
        bool with_xor)
    {
        Block blockR = new(ref_block);
        blockR.XorBlock(prev_block);
        Block Blocktmp = new(blockR);
        /* Now blockR = ref_block + prev_block and Blocktmp = ref_block + prev_block */
        if (with_xor)
        {
            /* Saving the next block contents for XOR over: */
            Blocktmp.XorBlock(next_block);
            /* Now blockR = ref_block + prev_block and
               Blocktmp = ref_block + prev_block + next_block */
        }

        /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
           (16,17,..31)... finally (112,113,...127) */
        for (int i = 0; i < 8; ++i)
        {
            BlamkaRoundRef.BLAKE2_ROUND_NOMSG(
                ref blockR.V[16 * i], ref blockR.V[16 * i + 1], ref blockR.V[16 * i + 2],
                ref blockR.V[16 * i + 3], ref blockR.V[16 * i + 4], ref blockR.V[16 * i + 5],
                ref blockR.V[16 * i + 6], ref blockR.V[16 * i + 7], ref blockR.V[16 * i + 8],
                ref blockR.V[16 * i + 9], ref blockR.V[16 * i + 10], ref blockR.V[16 * i + 11],
                ref blockR.V[16 * i + 12], ref blockR.V[16 * i + 13], ref blockR.V[16 * i + 14],
                ref blockR.V[16 * i + 15]);
        }

        /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
           (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
        for (int i = 0; i < 8; i++)
        {
            BlamkaRoundRef.BLAKE2_ROUND_NOMSG(
                ref blockR.V[2 * i], ref blockR.V[2 * i + 1], ref blockR.V[2 * i + 16],
                ref blockR.V[2 * i + 17], ref blockR.V[2 * i + 32], ref blockR.V[2 * i + 33],
                ref blockR.V[2 * i + 48], ref blockR.V[2 * i + 49], ref blockR.V[2 * i + 64],
                ref blockR.V[2 * i + 65], ref blockR.V[2 * i + 80], ref blockR.V[2 * i + 81],
                ref blockR.V[2 * i + 96], ref blockR.V[2 * i + 97], ref blockR.V[2 * i + 112],
                ref blockR.V[2 * i + 113]);
        }

        Block newBlock = new(Blocktmp);
        newBlock.XorBlock(blockR);
        return newBlock;
    }

    private static Block NextAddresses(
        Block address_block,
        Block input_block,
        in Block zero_block)
    {
        input_block.V[6]++;
        address_block = FillBlock(zero_block, input_block, address_block, false);
        address_block = FillBlock(zero_block, address_block, address_block, false);

        return address_block;
    }

    /// <summary>
    /// Function that fills the segment using previous segments also from other threads
    /// </summary>
    /// <param name="instance">Pointer to the current instance</param>
    /// <param name="position">Current position</param>
    public static void FillSegment(in Argon2Instance instance, Argon2Position position)
    {
        Block ref_block;
        Block address_block = new();
        Block input_block = new();
        Block zero_block = new();
        
        ulong pseudo_rand, ref_index, ref_lane;
        uint prev_offset, curr_offset;
        uint starting_index;
        uint i;

        if (instance is null)
            return;

        bool data_independent_addressing =
            (instance.type == Argon2Type.I) ||
            (instance.type == Argon2Type.ID && (position.pass == 0) && (position.slice < Consts.ARGON2_SYNC_POINTS / 2));

        if (data_independent_addressing)
        {
            zero_block = new(0);
            input_block = new(0);

            input_block.V[0] = position.pass;
            input_block.V[1] = position.lane;
            input_block.V[2] = position.slice;
            input_block.V[3] = instance.memory_blocks;
            input_block.V[4] = instance.passes;
            input_block.V[5] = (ulong)instance.type;
        }

        starting_index = 0;

        if ((0 == position.pass) && (0 == position.slice))
        {
            starting_index = 2; /* we have already generated the first two blocks */

            /* Don't forget to generate the first block of addresses: */
            if (data_independent_addressing)
            {
                address_block = NextAddresses(address_block, input_block, zero_block);
            }
        }

        /* Offset of the current block */
        curr_offset = position.lane * instance.lane_length +
                      position.slice * instance.segment_length + starting_index;

        if (0 == curr_offset % instance.lane_length)
        {
            /* Last block in this lane */
            prev_offset = curr_offset + instance.lane_length - 1;
        }
        else
        {
            /* Previous block */
            prev_offset = curr_offset - 1;
        }

        for (i = starting_index; i < instance.segment_length;
             ++i, ++curr_offset, ++prev_offset)
        {
            /*1.1 Rotating prev_offset if needed */
            if (curr_offset % instance.lane_length == 1)
            {
                prev_offset = curr_offset - 1;
            }

            /* 1.2 Computing the index of the reference block */
            /* 1.2.1 Taking pseudo-random value from the previous block */
            if (data_independent_addressing)
            {
                if (i % Consts.ARGON2_ADDRESSES_IN_BLOCK == 0)
                {
                    address_block = NextAddresses(address_block, input_block, zero_block);
                }
                pseudo_rand = address_block.V[i % Consts.ARGON2_ADDRESSES_IN_BLOCK];
            }
            else
            {
                pseudo_rand = instance.memory[prev_offset].V[0];
            }

            /* 1.2.2 Computing the lane of the reference block */
            ref_lane = (pseudo_rand >> 32) % instance.lanes;

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Cannot reference other lanes yet */
                ref_lane = position.lane;
            }

            /* 1.2.3 Computing the number of possible reference block within the
             * lane.
             */
            position.index = i;
            ref_index = instance.IndexAlpha(
                ref position,
                (uint)(pseudo_rand & 0xFFFFFFFFUL),
                ref_lane == position.lane);

            /* 2 Creating a new block */
            ref_block = instance.memory[instance.lane_length * ref_lane + ref_index];
            
            if (Argon2Version.ARGON2_VERSION_10 == instance.version)
            {
                /* version 1.2.1 and earlier: overwrite, not XOR */
                instance.memory[curr_offset] = FillBlock(
                    instance.memory[prev_offset],
                    ref_block,
                    instance.memory[curr_offset],
                    false);
            }
            else
            {
                if (0 == position.pass)
                {
                    instance.memory[curr_offset] = FillBlock(
                        instance.memory[prev_offset],
                        ref_block,
                        instance.memory[curr_offset],
                        false);
                }
                else
                {
                    instance.memory[curr_offset] = FillBlock(
                        instance.memory[prev_offset],
                        ref_block,
                        instance.memory[curr_offset],
                        true);
                }
            }
        }
    }
}
