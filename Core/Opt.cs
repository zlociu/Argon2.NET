//namespace Argon2;

//using System.Runtime.Intrinsics;

//public class Opt
//{
//    /// <summary>
//    /// Function fills a new memory block and optionally XORs the old block over the new one.
//    /// </summary>
//    /// <param name="state">state Pointer to the just produced block. Content will be updated(!)</param>
//    /// <param name="ref_block">Pointer to the reference block</param>
//    /// <param name="next_block">Pointer to the block to be XORed over. May coincide with ref_block/></param>
//    /// <param name="with_xor">Whether to XOR into the new block or just overwrite </param>
//    public static void FillBlock(
//        Vector512<ulong>[] state,
//        in Block ref_block,
//        Block next_block,
//        bool with_xor)
//    {
//        Vector512<ulong>[] BlockXY = new Vector512<ulong>[Consts.ARGON2_512BIT_WORDS_IN_BLOCK];
//        int i;

//        int ulongsInVector = Vector512<ulong>.Count;

//        if (with_xor)
//        {
//            var refSpan = ref_block.V.AsSpan();
//            var nextSpan = next_block.V.AsSpan();

//            for (i = 0; i < Consts.ARGON2_512BIT_WORDS_IN_BLOCK; i++)
//            {
//                state[i] = Vector512.Xor(state[i], Vector512.Create<ulong>(refSpan[(ulongsInVector * i)..]));
//                BlockXY[i] = Vector512.Xor(state[i], Vector512.Create<ulong>(nextSpan[(ulongsInVector * i)..]));
//            }
//        }
//        else
//        {
//            var refSpan = ref_block.V.AsSpan();

//            for (i = 0; i < Consts.ARGON2_512BIT_WORDS_IN_BLOCK; i++)
//            {
//                BlockXY[i] = state[i] = Vector512.Xor(state[i], Vector512.Create<ulong>(refSpan[(8 * i)..]));
//            }
//        }

//        for (i = 0; i < 2; ++i)
//        {
//            BLAKE2_ROUND_1(
//                state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
//                state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]);
//        }

//        for (i = 0; i < 2; ++i)
//        {
//            BLAKE2_ROUND_2(
//                state[2 * 0 + i], state[2 * 1 + i], state[2 * 2 + i], state[2 * 3 + i],
//                state[2 * 4 + i], state[2 * 5 + i], state[2 * 6 + i], state[2 * 7 + i]);
//        }

//        var span = next_block.V.AsSpan();

//        for (i = 0; i < Consts.ARGON2_512BIT_WORDS_IN_BLOCK; i++)
//        {
//            state[i] = Vector512.Xor(state[i], BlockXY[i]);
//            state[i].CopyTo(next_block.V, i * ulongsInVector);
//        }
//    }

    

//    public static void NextAddresses(Block address_block, Block input_block)
//    {
//        /*Temporary zero-initialized blocks*/
//        Vector512<ulong>[] zero_block = new Vector512<ulong>[Consts.ARGON2_512BIT_WORDS_IN_BLOCK];
//        Vector512<ulong>[] zero2_block = new Vector512<ulong>[Consts.ARGON2_512BIT_WORDS_IN_BLOCK];

//        /*Increasing index counter*/
//        input_block.V[6]++;

//        /*First iteration of G*/
//        FillBlock(zero_block, input_block, address_block, false);

//        /*Second iteration of G*/
//        FillBlock(zero2_block, address_block, address_block, false);
//    }

//    public void FillSegment(in Argon2Instance instance, Argon2Position position)
//    {
//        Block ref_block;
//        Block curr_block;

//        Block address_block = new();
//        Block input_block = new();

//        ulong pseudo_rand, ref_index, ref_lane;
//        uint prev_offset, curr_offset;
//        uint starting_index, i;
        
//        Vector512<ulong>[] state = new Vector512<ulong>[Consts.ARGON2_512BIT_WORDS_IN_BLOCK];

//        bool data_independent_addressing;

//        if (instance is null)
//            return;

//        data_independent_addressing =
//            (instance.type == Argon2Type.I) ||
//            (instance.type == Argon2Type.ID && (position.pass == 0) &&
//             (position.slice < Consts.ARGON2_SYNC_POINTS / 2));

//        if (data_independent_addressing)
//        {
//            input_block = new Block(0);

//            input_block.V[0] = position.pass;
//            input_block.V[1] = position.lane;
//            input_block.V[2] = position.slice;
//            input_block.V[3] = instance.memory_blocks;
//            input_block.V[4] = instance.passes;
//            input_block.V[5] = (ulong)instance.type;
//        }

//        starting_index = 0;

//        if ((0 == position.pass) && (0 == position.slice))
//        {
//            starting_index = 2; /* we have already generated the first two blocks */

//            /* Don't forget to generate the first block of addresses: */
//            if (data_independent_addressing)
//            {
//                NextAddresses(address_block, input_block);
//            }
//        }

//        /* Offset of the current block */
//        curr_offset = position.lane * instance.lane_length +
//                      position.slice * instance.segment_length + starting_index;

//        if (0 == curr_offset % instance.lane_length)
//        {
//            /* Last block in this lane */
//            prev_offset = curr_offset + instance.lane_length - 1;
//        }
//        else
//        {
//            /* Previous block */
//            prev_offset = curr_offset - 1;
//        }
        
//        memcpy(state, ((instance.memory + prev_offset).v), Consts.ARGON2_BLOCK_SIZE);

//        for (i = starting_index; i < instance.segment_length;
//             ++i, ++curr_offset, ++prev_offset)
//        {
//            /*1.1 Rotating prev_offset if needed */
//            if (curr_offset % instance.lane_length == 1)
//            {
//                prev_offset = curr_offset - 1;
//            }

//            /* 1.2 Computing the index of the reference block */
//            /* 1.2.1 Taking pseudo-random value from the previous block */
//            if (data_independent_addressing)
//            {
//                if (i % Consts.ARGON2_ADDRESSES_IN_BLOCK == 0)
//                {
//                    NextAddresses(address_block, input_block);
//                }
//                pseudo_rand = address_block.V[i % Consts.ARGON2_ADDRESSES_IN_BLOCK];
//            }
//            else
//            {
//                pseudo_rand = instance.memory[prev_offset].v[0];
//            }

//            /* 1.2.2 Computing the lane of the reference block */
//            ref_lane = ((pseudo_rand >> 32)) % instance.lanes;

//            if ((position.pass == 0) && (position.slice == 0))
//            {
//                /* Can not reference other lanes yet */
//                ref_lane = position.lane;
//            }

//            /* 1.2.3 Computing the number of possible reference block within the
//             * lane.
//             */
//            position.index = i;
//            ref_index = Core.IndexAlpha(
//                instance,
//                ref position,
//                (uint)(pseudo_rand & 0xFFFFFFFFUL),
//                ref_lane == position.lane);

//            /* 2 Creating a new block */
//            ref_block =
//                instance.memory + instance.lane_length * ref_lane + ref_index;
//            curr_block = instance.memory + curr_offset;
//            if (Argon2Version.ARGON2_VERSION_10 == instance.version)
//            {
//                /* version 1.2.1 and earlier: overwrite, not XOR */
//                FillBlock(state, ref_block, curr_block, false);
//            }
//            else
//            {
//                if (0 == position.pass)
//                    FillBlock(state, ref_block, curr_block, false);
//                else
//                    FillBlock(state, ref_block, curr_block, true);
//            }
//        }
//    }
//}
