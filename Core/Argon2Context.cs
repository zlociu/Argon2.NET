namespace Argon2.Core;

using Enums;


/// <summary>
/// Context: structure to hold Argon2 inputs:
/// <list type="bullet">
/// <item> output array </item>
/// <item> password </item>
/// <item> salt </item>
/// <item> secret </item>
/// <item> associated data </item>
/// <item> number of passes </item>
/// <item> amount of used memory(in KBytes, can be rounded up a bit) </item>
/// <item> number of parallel threads that will be run </item>
/// </list>
/// All the parameters above affect the output hash value.
/// </summary>
public class Argon2Context
{
    public byte[] Out;       // output array
    public byte[] Pwd;      // password array
    public byte[] Salt;     // salt array
    public byte[] Secret;   // key array
    public byte[] Ad;       // associated data array
    public uint TCost;     // number of passes
    public uint MCost;     // amount of memory requested (KB)
    public uint Lanes;      // number of lanes
    public uint Threads;    // maximum number of threads
    public Argon2Version Version;
                            // version number //
    public uint Flags;      // array of bool options //


    /// <summary>
    /// Function that validates all inputs against predefined restrictions and return an error code
    /// </summary>
    /// <returns>ARGON2_OK if everything is all right, otherwise one of error codes </returns>
    public Argon2_ErrorCodes ValidateInputs()
    {
        if (this.Out.Length == 0)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_PTR_NULL;

        // Validate output length //
        if (Consts.ARGON2_MIN_OUTLEN > this.Out.LongLength)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_SHORT;

        if (Consts.ARGON2_MAX_OUTLEN < this.Out.LongLength)
            return Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_LONG;

        // Validate password (required param) //
        if (this.Pwd.Length == 0)
            return Argon2_ErrorCodes.ARGON2_PWD_PTR_MISMATCH;

        if (Consts.ARGON2_MIN_PWD_LENGTH > this.Pwd.LongLength)
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_SHORT;

        if (Consts.ARGON2_MAX_PWD_LENGTH < this.Pwd.LongLength)
            return Argon2_ErrorCodes.ARGON2_PWD_TOO_LONG;

        // Validate salt (required param) //
        if (this.Salt.Length == 0)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_PTR_MISMATCH;
        }

        if (Consts.ARGON2_MIN_SALT_LENGTH > this.Salt.LongLength)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_TOO_SHORT;
        }

        if (Consts.ARGON2_MAX_SALT_LENGTH < this.Salt.LongLength)
        {
            return Argon2_ErrorCodes.ARGON2_SALT_TOO_LONG;
        }

        // Validate secret (optional param)
        if (Consts.ARGON2_MIN_SECRET > this.Secret.LongLength)
            return Argon2_ErrorCodes.ARGON2_SECRET_TOO_SHORT;

        if (Consts.ARGON2_MAX_SECRET < this.Secret.LongLength)
            return Argon2_ErrorCodes.ARGON2_SECRET_TOO_LONG;

        // Validate associated data (optional param)
        if (Consts.ARGON2_MIN_AD_LENGTH > this.Ad.LongLength)
            return Argon2_ErrorCodes.ARGON2_AD_TOO_SHORT;

        if (Consts.ARGON2_MAX_AD_LENGTH < this.Ad.LongLength)
            return Argon2_ErrorCodes.ARGON2_AD_TOO_LONG;

        // Validate memory cost 
        if (Consts.ARGON2_MIN_MEMORY > this.MCost)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_LITTLE;

        if (Consts.ARGON2_MAX_MEMORY < this.MCost)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_MUCH;

        if (this.MCost < 8 * this.Lanes)
            return Argon2_ErrorCodes.ARGON2_MEMORY_TOO_LITTLE;

        // Validate time cost
        if (Consts.ARGON2_MIN_TIME > this.TCost)
            return Argon2_ErrorCodes.ARGON2_TIME_TOO_SMALL;

        if (Consts.ARGON2_MAX_TIME < this.TCost)
            return Argon2_ErrorCodes.ARGON2_TIME_TOO_LARGE;

        // Validate lanes 
        if (Consts.ARGON2_MIN_LANES > this.Lanes)
            return Argon2_ErrorCodes.ARGON2_LANES_TOO_FEW;

        if (Consts.ARGON2_MAX_LANES < this.Lanes)
            return Argon2_ErrorCodes.ARGON2_LANES_TOO_MANY;

        // Validate threads 
        if (Consts.ARGON2_MIN_THREADS > this.Threads)
            return Argon2_ErrorCodes.ARGON2_THREADS_TOO_FEW;

        if (Consts.ARGON2_MAX_THREADS < this.Threads)
            return Argon2_ErrorCodes.ARGON2_THREADS_TOO_MANY;

        return Argon2_ErrorCodes.ARGON2_OK;
    }
}
