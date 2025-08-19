namespace Argon2.Core;

internal class Consts
{
    public const uint ARGON2_MIN_LANES = 1;
    public const uint ARGON2_MAX_LANES = 0xFFFFFF;

    /* Minimum and maximum number of threads */
    public const uint ARGON2_MIN_THREADS = 1;
    public const uint ARGON2_MAX_THREADS = 0xFFFFFF;

    /* Number of synchronization points between lanes per pass */
    public const uint ARGON2_SYNC_POINTS = 4;

    /* Minimum and maximum digest size in bytes */
    public const uint ARGON2_MIN_OUTLEN = 4;
    public const uint ARGON2_MAX_OUTLEN = 0xFFFFFFFF;

    /* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
    public const uint ARGON2_MIN_MEMORY = 2 * ARGON2_SYNC_POINTS; /* 2 blocks per slice */

    /* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
    public static readonly int ARGON2_MAX_MEMORY_BITS = Math.Min(32, sizeof(long) * 8 - 11);
    public static readonly uint ARGON2_MAX_MEMORY = (uint)Math.Min(0xFFFFFFFFUL, (ulong)(1L << ARGON2_MAX_MEMORY_BITS));

    /* Minimum and maximum number of passes */
    public const uint ARGON2_MIN_TIME = 1;
    public const uint ARGON2_MAX_TIME = 0xFFFFFFFF;

    /* Minimum and maximum password length in bytes */
    public const uint ARGON2_MIN_PWD_LENGTH = 0;
    public const uint ARGON2_MAX_PWD_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum associated data length in bytes */
    public const uint ARGON2_MIN_AD_LENGTH = 0;
    public const uint ARGON2_MAX_AD_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum salt length in bytes */
    public const uint ARGON2_MIN_SALT_LENGTH = 8;
    public const uint ARGON2_MAX_SALT_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum key length in bytes */
    public const uint ARGON2_MIN_SECRET = 0;
    public const uint ARGON2_MAX_SECRET = 0xFFFFFFFF;

    /* Flags to determine which fields are securely wiped (default = no wipe). */
    public const uint ARGON2_DEFAULT_FLAGS = 0;
    public const uint ARGON2_FLAG_CLEAR_PASSWORD = 1;
    public const uint ARGON2_FLAG_CLEAR_SECRET = 2;

    public const int ARGON2_BLOCK_SIZE = 1024;
    public const int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;
    public const int ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16;
    public const int ARGON2_HWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 32;
    public const int ARGON2_512BIT_WORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 64;
    public const int ARGON2_ADDRESSES_IN_BLOCK = 128;
    public const int ARGON2_PREHASH_DIGEST_LENGTH = 64;
    public const int ARGON2_PREHASH_SEED_LENGTH = 72;
}
