namespace Argon2.Enums;

public enum Argon2_ErrorCodes
{
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
}

public static class Argon2_ErrorCodes_Extensions
{
    public static string GetErrorMessage(this Argon2_ErrorCodes error_code)
    {
        return error_code switch
        {
            Argon2_ErrorCodes.ARGON2_OK => "OK",
            Argon2_ErrorCodes.ARGON2_OUTPUT_PTR_NULL => "Output pointer is NULL",
            Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_SHORT => "Output is too short",
            Argon2_ErrorCodes.ARGON2_OUTPUT_TOO_LONG => "Output is too long",
            Argon2_ErrorCodes.ARGON2_PWD_TOO_SHORT => "Password is too short",
            Argon2_ErrorCodes.ARGON2_PWD_TOO_LONG => "Password is too long",
            Argon2_ErrorCodes.ARGON2_SALT_TOO_SHORT => "Salt is too short",
            Argon2_ErrorCodes.ARGON2_SALT_TOO_LONG => "Salt is too long",
            Argon2_ErrorCodes.ARGON2_AD_TOO_SHORT => "Associated data is too short",
            Argon2_ErrorCodes.ARGON2_AD_TOO_LONG => "Associated data is too long",
            Argon2_ErrorCodes.ARGON2_SECRET_TOO_SHORT => "Secret is too short",
            Argon2_ErrorCodes.ARGON2_SECRET_TOO_LONG => "Secret is too long",
            Argon2_ErrorCodes.ARGON2_TIME_TOO_SMALL => "Time cost is too small",
            Argon2_ErrorCodes.ARGON2_TIME_TOO_LARGE => "Time cost is too large",
            Argon2_ErrorCodes.ARGON2_MEMORY_TOO_LITTLE => "Memory cost is too small",
            Argon2_ErrorCodes.ARGON2_MEMORY_TOO_MUCH => "Memory cost is too large",
            Argon2_ErrorCodes.ARGON2_LANES_TOO_FEW => "Too few lanes",
            Argon2_ErrorCodes.ARGON2_LANES_TOO_MANY => "Too many lanes",
            Argon2_ErrorCodes.ARGON2_PWD_PTR_MISMATCH => "Password pointer is NULL, but password length is not 0",
            Argon2_ErrorCodes.ARGON2_SALT_PTR_MISMATCH => "Salt pointer is NULL, but salt length is not 0",
            Argon2_ErrorCodes.ARGON2_SECRET_PTR_MISMATCH => "Secret pointer is NULL, but secret length is not 0",
            Argon2_ErrorCodes.ARGON2_AD_PTR_MISMATCH => "Associated data pointer is NULL, but ad length is not 0",
            Argon2_ErrorCodes.ARGON2_MEMORY_ALLOCATION_ERROR => "Memory allocation error",
            Argon2_ErrorCodes.ARGON2_FREE_MEMORY_CBK_NULL => "The free memory callback is NULL",
            Argon2_ErrorCodes.ARGON2_ALLOCATE_MEMORY_CBK_NULL => "The allocate memory callback is NULL",
            Argon2_ErrorCodes.ARGON2_INCORRECT_PARAMETER => "Argon2Context context is NULL",
            Argon2_ErrorCodes.ARGON2_INCORRECT_TYPE => "There is no such version of Argon2",
            Argon2_ErrorCodes.ARGON2_OUT_PTR_MISMATCH => "Output pointer mismatch",
            Argon2_ErrorCodes.ARGON2_THREADS_TOO_FEW => "Not enough threads",
            Argon2_ErrorCodes.ARGON2_THREADS_TOO_MANY => "Too many threads",
            Argon2_ErrorCodes.ARGON2_MISSING_ARGS => "Missing arguments",
            Argon2_ErrorCodes.ARGON2_ENCODING_FAIL => "Encoding failed",
            Argon2_ErrorCodes.ARGON2_DECODING_FAIL => "Decoding failed",
            Argon2_ErrorCodes.ARGON2_THREAD_FAIL => "Threading failure",
            Argon2_ErrorCodes.ARGON2_DECODING_LENGTH_FAIL => "Some of encoded parameters are too long or too short",
            Argon2_ErrorCodes.ARGON2_VERIFY_MISMATCH => "The password does not match the supplied hash",
            _ => "Unknown error code"
        };
    }
}