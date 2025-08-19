namespace Argon2.Core;

using global::Argon2.Enums;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

/*
 * Context: structure to hold Argon2 inputs:
 *  output array and its length,
 *  password and its length,
 *  salt and its length,
 *  secret and its length,
 *  associated data and its length,
 *  number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 *  number of parallel threads that will be run.
 * All the parameters above affect the output hash value.
 */
public class Argon2Context
{
    public byte[] _out;    // output array //
 
    public byte[] pwd;    // password array //

    public byte[] salt;    // salt array //

    public byte[] secret;    // key array //

    public byte[] ad;    // associated data array //
 
    public uint t_cost;  // number of passes //
    public uint m_cost;  // amount of memory requested (KB) //
    public uint lanes;   // number of lanes //
    public uint threads; // maximum number of threads //

    public Argon2Version version; // version number //

    public uint flags; // array of bool options //


    /// <summary>
    /// Function that validates all inputs against predefined restrictions and return an error code
    /// </summary>
    /// <returns>ARGON2_OK if everything is all right, otherwise one of error codes </returns>
    public Argon2_ErrorCodes ValidateInputs()
    {
        if (this._out.Length == 0)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_PTR_NULL;

        // Validate output length //
        if (Consts.ARGON2_MIN_OUTLEN > this._out.LongLength)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_SHORT;

        if (Consts.ARGON2_MAX_OUTLEN < this._out.LongLength)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_LONG;

        // Validate password (required param) //
        if (this.pwd.Length == 0)
            return Argon2_ErrorCodes.ARGON2_PWD_PTR_MISMATCH;

        if (Consts.ARGON2_MIN_PWD_LENGTH > this.pwd.LongLength)
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_SHORT;

        if (Consts.ARGON2_MAX_PWD_LENGTH < this.pwd.LongLength)
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_LONG;

        // Validate salt (required param) //
        if (this.salt.Length == 0)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_PTR_MISMATCH;
        }

        if (Consts.ARGON2_MIN_SALT_LENGTH > this.salt.LongLength)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_TOO_SHORT;
        }

        if (Consts.ARGON2_MAX_SALT_LENGTH < this.salt.LongLength)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_TOO_LONG;
        }

        // Validate secret (optional param)
        if (Consts.ARGON2_MIN_SECRET > this.secret.LongLength)
            return Argon2_ErrorCodes.ARGON2_SECRET_TOO_SHORT;

        if (Consts.ARGON2_MAX_SECRET < this.secret.LongLength)
            return Argon2_ErrorCodes.ARGON2_SECRET_TOO_LONG;

        // Validate associated data (optional param)
        if (Consts.ARGON2_MIN_AD_LENGTH > this.ad.LongLength)
            return Argon2_ErrorCodes.ARGON2_AD_TOO_SHORT;
            
        if (Consts.ARGON2_MAX_AD_LENGTH < this.ad.LongLength)
            return Argon2_ErrorCodes.ARGON2_AD_TOO_LONG;

        // Validate memory cost 
        if (Consts.ARGON2_MIN_MEMORY > this.m_cost)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_LITTLE;

        if (Consts.ARGON2_MAX_MEMORY < this.m_cost)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_MUCH;

        if (this.m_cost < 8 * this.lanes)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_LITTLE;

        // Validate time cost
        if (Consts.ARGON2_MIN_TIME > this.t_cost)
            return Argon2_ErrorCodes.ARGON2_TIME_TOO_SMALL;

        if (Consts.ARGON2_MAX_TIME < this.t_cost)
            return Argon2_ErrorCodes.ARGON2_TIME_TOO_LARGE;

        // Validate lanes 
        if (Consts.ARGON2_MIN_LANES > this.lanes)
            return Argon2_ErrorCodes.ARGON2_LANES_TOO_FEW;

        if (Consts.ARGON2_MAX_LANES < this.lanes)
            return Argon2_ErrorCodes.ARGON2_LANES_TOO_MANY;

        // Validate threads 
        if (Consts.ARGON2_MIN_THREADS > this.threads)
            return Argon2_ErrorCodes.ARGON2_THREADS_TOO_FEW;

        if (Consts.ARGON2_MAX_THREADS < this.threads)
            return Argon2_ErrorCodes.ARGON2_THREADS_TOO_MANY;

        return Argon2_ErrorCodes.ARGON2_OK;
    }
}

/* Version of the algorithm */
public enum Argon2Version
{
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
}

public class Argon2
{
    public static Argon2_ErrorCodes Argon2Hash(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        byte[] pwd,
        byte[] salt,
        uint hashLen,
        Argon2Type type,
        Argon2Version version,
        out Argon2Context context)
    {
        context = new();

        if (pwd.LongLength > Consts.ARGON2_MAX_PWD_LENGTH)
        {
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_LONG;
        }

        if (salt.LongLength > Consts.ARGON2_MAX_SALT_LENGTH)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_TOO_LONG;
        }

        if (hashLen > Consts.ARGON2_MAX_OUTLEN)
        {
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_LONG;
        }

        if (hashLen < Consts.ARGON2_MIN_OUTLEN)
        {
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_SHORT;
        }

        context._out = new byte[hashLen];
        context.pwd = pwd;
        context.salt = salt;
        context.secret = [];
        context.ad = [];
        context.t_cost = t_cost;
        context.m_cost = m_cost;
        context.lanes = parallelism;
        context.threads = parallelism;
        context.flags = Consts.ARGON2_DEFAULT_FLAGS;
        context.version = version;

        return Argon2Ctx(context, type);
    }

    public static Argon2_ErrorCodes Argon2Verify(string encoded, in byte[] pwd, Argon2Type type)
    {
        Argon2Context ctx = new();
        byte[] desired_result;

        if (pwd.LongLength > Consts.ARGON2_MAX_PWD_LENGTH)
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_LONG;

        if (encoded is null)
            return Argon2_ErrorCodes.ARGON2_DECODING_FAIL;

        // No field can be longer than the encoded length //
        ctx.pwd = pwd;

        Argon2_ErrorCodes ret = Encoding.DecodeString(encoded, type, ctx);
        if (ret != Argon2_ErrorCodes.ARGON2_OK)
            return ret;

        // Set aside the desired result, and get a new buffer. //
        desired_result = ctx._out;

        var outLen = ctx._out.Length;
        ctx._out = new byte[outLen];

        ret = Argon2Verify_ctx(ctx, desired_result, type);

        return ret;
    }

    private static Argon2_ErrorCodes Argon2Ctx(Argon2Context context, Argon2Type type)
    {
        // 1. Validate all inputs //
        var result = context.ValidateInputs();
        if (Argon2_ErrorCodes.ARGON2_OK != result)
            return result;

        Argon2Instance instance = new(context, type);

        // 3. Initialization: Hashing inputs, allocating memory, filling first blocks
        instance.Initialize();

        // 4. Filling memory //
        result = instance.FillMemoryBlocks();

        if (Argon2_ErrorCodes.ARGON2_OK != result)
            return result;
        // 5. Finalization //
        instance.Finish();

        return Argon2_ErrorCodes.ARGON2_OK;
    }

    private static Argon2_ErrorCodes Argon2Verify_ctx(Argon2Context context, in byte[] hash, Argon2Type type)
    {
        Argon2_ErrorCodes ret = Argon2Ctx(context, type);
        if (ret != Argon2_ErrorCodes.ARGON2_OK)
            return ret;
        
        if (!Argon2Compare(hash, context._out))
            return Argon2_ErrorCodes.ARGON2_VERIFY_MISMATCH;

        return Argon2_ErrorCodes.ARGON2_OK;
    }

    private static bool Argon2Compare(in byte[] b1, in byte[] b2)
    {
        if (b1.LongLength != b2.LongLength)
            return false;

        for (long i = 0L; i < b1.LongLength; i++)
        {
            if (b1[i] != b2[i])
                return false;
        }

        return true;
    }

    public static int Argon2EncodedLen(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        int saltlen,
        int hashlen,
        Argon2Type type)
    {
        static int b64len(int len)
        {
            int olen = (len / 3) << 2;

            return (len % 3 switch
            {
                2 => olen + 1,
                1 => olen + 2,
                _ => olen
            });
        }

        return "$$v=$m=,t=,p=$$".Length + type.ToString().Length +
               t_cost.ToString().Length + m_cost.ToString().Length + parallelism.ToString().Length +
               b64len(saltlen) + b64len(hashlen) + 2 + 1; // 2 = ArgonVersion number len
    }
}
