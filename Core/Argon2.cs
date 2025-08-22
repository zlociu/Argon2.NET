namespace Argon2.Core;

using Enums;


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

        context.Out = new byte[hashLen];
        context.Pwd = pwd;
        context.Salt = salt;
        context.Secret = [];
        context.Ad = [];
        context.TCost = t_cost;
        context.MCost = m_cost;
        context.Lanes = parallelism;
        context.Threads = parallelism;
        context.Flags = Consts.ARGON2_DEFAULT_FLAGS;
        context.Version = version;

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
        ctx.Pwd = pwd;

        Argon2_ErrorCodes ret = Encoding.DecodeString(encoded, type, ctx);
        if (ret != Argon2_ErrorCodes.ARGON2_OK)
            return ret;

        // Set aside the desired result, and get a new buffer. //
        desired_result = ctx.Out;

        var outLen = ctx.Out.Length;
        ctx.Out = new byte[outLen];

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
        
        if (!Argon2Compare(hash, context.Out))
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
