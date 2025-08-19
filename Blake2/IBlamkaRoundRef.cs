namespace Argon2.Blake2;

using System.Runtime.CompilerServices;

/* designed by the Lyra PHC team */
public class BlamkaRoundRef
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong fBlaMka(ulong x, ulong y)
    {
        const ulong m = 0xFFFFFFFFLU;
        ulong xy = (x & m) * (y & m);
        return x + y + (xy << 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
    {
        a = fBlaMka(a, b);                                                     
        d = BitOperations.RotateRight(d ^ a, 32);                              
        c = fBlaMka(c, d);                                                     
        b = BitOperations.RotateRight(b ^ c, 24);                              
        a = fBlaMka(a, b);                                                     
        d = BitOperations.RotateRight(d ^ a, 16);                              
        c = fBlaMka(c, d);                                                     
        b = BitOperations.RotateRight(b ^ c, 63);                              
    }
    
    public static void BLAKE2_ROUND_NOMSG(
        ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3,
        ref ulong v4, ref ulong v5, ref ulong v6, ref ulong v7,
        ref ulong v8, ref ulong v9, ref ulong v10, ref ulong v11,
        ref ulong v12, ref ulong v13, ref ulong v14, ref ulong v15)
    {
        G(ref v0, ref v4, ref v8, ref v12);
        G(ref v1, ref v5, ref v9, ref v13);
        G(ref v2, ref v6, ref v10, ref v14);
        G(ref v3, ref v7, ref v11, ref v15);
        G(ref v0, ref v5, ref v10, ref v15);                                                 
        G(ref v1, ref v6, ref v11, ref v12);                                                 
        G(ref v2, ref v7, ref v8, ref v13);                                                  
        G(ref v3, ref v4, ref v9, ref v14);                                                  
    }
}
