namespace Argon2.Enums;

/* Version of the algorithm */
public enum Argon2Type
{
    D = 0,
    I = 1,
    ID = 2
}

public static class Argon2Type_Extensions
{
    public static string Argon2Type2string(this Argon2Type type, bool uppercase)
    {
        return type switch
        {
            Argon2Type.D => uppercase ? "Argon2d" : "argon2d",
            Argon2Type.I => uppercase ? "Argon2i" : "argon2i",
            Argon2Type.ID => uppercase ? "Argon2id" : "argon2id",
            _ => string.Empty
        };
    }
}