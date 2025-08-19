using Argon2.Enums;

namespace Argon2;

public interface IArgon2
{
    /* generic function underlying the above ones */
     int Argon2Hash(
        uint t_cost, uint m_cost,
        uint parallelism, byte[] pwd,
        long pwdlen, byte[] salt,
        long saltlen, byte[] hash,
        long hashlen, Argon2Type type,
        uint version);

    /* generic function underlying the above ones */
     int Argon2Verify(string encoded, byte[] pwd, long pwdlen, Argon2Type type);
}
