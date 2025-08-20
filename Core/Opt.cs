namespace Argon2;

using Argon2.Core;
using Argon2.Enums;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

internal class Opt
{
    /// <summary>
    /// Function fills a new memory block and optionally XORs the old block over the new one.
    /// </summary>
    /// <param name="state">state Pointer to the just produced block. Content will be updated(!)</param>
    /// <param name="ref_block">Pointer to the reference block</param>
    /// <param name="next_block">Pointer to the block to be XORed over. May coincide with ref_block/></param>
    /// <param name="with_xor">Whether to XOR into the new block or just overwrite </param>
    private static Block FillBlock(
        Vector256<ulong>[] state,
        Block ref_block,
        Block next_block,
        bool with_xor)
    {
        Vector256<ulong>[] block_XY = new Vector256<ulong>[Consts.ARGON2_HWORDS_IN_BLOCK];

        if (with_xor)
        {
            for (int i = 0; i < Consts.ARGON2_HWORDS_IN_BLOCK; i++)
            {
                state[i] = Avx2.Xor(state[i], Vector256.Create<ulong>(ref_block.V, 4 * i));
                block_XY[i] = Avx2.Xor(state[i], Vector256.Create<ulong>(next_block.V, 4 * i));
            }
        } 
        else
        {
            for (int i = 0; i < Consts.ARGON2_HWORDS_IN_BLOCK; i++)
            {
                block_XY[i] = state[i] = Avx2.Xor(state[i], Vector256.Create<ulong>(ref_block.V, 4 * i));
            }
        }

        for (int i = 0; i < 4; ++i)
        {
            BlamkaOpt.Blake2Round1(
                ref state[8 * i + 0], ref state[8 * i + 4], ref state[8 * i + 1], ref state[8 * i + 5],
                ref state[8 * i + 2], ref state[8 * i + 6], ref state[8 * i + 3], ref state[8 * i + 7]);
        }

        for (int i = 0; i < 4; ++i)
        {
            BlamkaOpt.Blake2Round2(
                ref state[0 + i], ref state[4 + i], ref state[8 + i], ref state[12 + i],
                ref state[16 + i], ref state[20 + i], ref state[24 + i], ref state[28 + i]);
        }

        var newBlock = new Block();

        for (int i = 0; i < Consts.ARGON2_HWORDS_IN_BLOCK; i++)
        {
            state[i] = Avx2.Xor(state[i], block_XY[i]);
            state[i].CopyTo(newBlock.V, i * 4);
        }

        return newBlock;
    }

    static Block NextAddresses(
        Block address_block,
        Block input_block)
    {
        /*Temporary zero-initialized blocks*/
    
        var zero_block = new Vector256<ulong>[Consts.ARGON2_HWORDS_IN_BLOCK];
        var zero2_block = new Vector256<ulong>[Consts.ARGON2_HWORDS_IN_BLOCK];

        /*Increasing index counter*/
        input_block.V[6]++;

        /*First iteration of G*/
        address_block = FillBlock(zero_block, input_block, address_block, false);

        /*Second iteration of G*/
        address_block = FillBlock(zero2_block, address_block, address_block, false);

        return address_block;
    }

    public static void FillSegment(in Argon2Instance instance, Argon2Position position)
    {
        Block ref_block;
        Block address_block = new();
        Block input_block = new();
        
        ulong pseudo_rand, ref_index, ref_lane;
        uint prev_offset, curr_offset;
        int starting_index, i;

        Vector256<ulong>[] state = new Vector256<ulong>[Consts.ARGON2_HWORDS_IN_BLOCK];

        bool data_independent_addressing;

        if (instance is null)
            return;

        data_independent_addressing =
            (instance.type == Argon2Type.I) ||
            (instance.type == Argon2Type.ID && (position.pass == 0) && (position.slice < Consts.ARGON2_SYNC_POINTS / 2));

        if (data_independent_addressing)
        {
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
                address_block = NextAddresses(address_block, input_block);
            }
        }

        /* Offset of the current block */
        curr_offset = position.lane * instance.lane_length +
                      position.slice * instance.segment_length + (uint)starting_index;

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

        for (i = 0; i < Consts.ARGON2_HWORDS_IN_BLOCK; i++)
        {
            state[i] = Vector256.Create<ulong>(instance.memory[prev_offset].V, 4 * i);
        }

        for (i = starting_index; i < instance.segment_length; ++i, ++curr_offset, ++prev_offset)
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
                    address_block = NextAddresses(address_block, input_block);
                }
                pseudo_rand = address_block.V[i % Consts.ARGON2_ADDRESSES_IN_BLOCK];
            }
            else
            {
                pseudo_rand = instance.memory[prev_offset].V[0];
            }

            /* 1.2.2 Computing the lane of the reference block */
            ref_lane = ((pseudo_rand >> 32)) % instance.lanes;

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Can not reference other lanes yet */
                ref_lane = position.lane;
            }

            /* 1.2.3 Computing the number of possible reference block within the
             * lane.
             */
            position.index = (uint)i;
            ref_index = instance.IndexAlpha(
                ref position,
                (uint)pseudo_rand & 0xFFFFFFFF,
                ref_lane == position.lane);

            /* 2 Creating a new block */
            ref_block = instance.memory[instance.lane_length * ref_lane + ref_index];

            if (Argon2Version.ARGON2_VERSION_10 == instance.version)
            {
                /* version 1.2.1 and earlier: overwrite, not XOR */
                instance.memory[curr_offset] = FillBlock(state, ref_block, instance.memory[curr_offset], false);
            }
            else
            {
                if (0 == position.pass)
                {
                    instance.memory[curr_offset] = FillBlock(state, ref_block, instance.memory[curr_offset], false);
                }
                else
                {
                    instance.memory[curr_offset] = FillBlock(state, ref_block, instance.memory[curr_offset], true);
                }
            }
        }
    }
}
