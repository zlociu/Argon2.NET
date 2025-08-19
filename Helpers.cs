using Argon2.Core;
using System.Text;

namespace Argon2;

public static class Helpers
{
    public static void PrintHelp(string cmd)
    {
        Console.Write("Usage:  {0} [-h] salt [-i|-d|-id] [-t iterations] " +
               "[-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] " +
               "[-l hash length] [-e|-r] [-v (10|13)]\n",
               cmd);
        Console.Write("\tPassword is read from stdin\n");
        Console.Write("Parameters:\n");
        Console.Write("\tsalt\t\tThe salt to use, at least 8 characters\n");
        Console.Write("\t-i\t\tUse Argon2i (this is the default)\n");
        Console.Write("\t-d\t\tUse Argon2d instead of Argon2i\n");
        Console.Write("\t-id\t\tUse Argon2id instead of Argon2i\n");
        Console.Write("\t-t N\t\tSets the number of iterations to N (default = {0})\n",
               3);
        Console.Write("\t-m N\t\tSets the memory usage of 2^N KiB (default {0})\n",
               12);
        Console.Write("\t-k N\t\tSets the memory usage of N KiB (default {0})\n",
               1 << 12);
        Console.Write("\t-p N\t\tSets parallelism to N threads (default {0})\n",
               1);
        Console.Write("\t-l N\t\tSets hash output length to N bytes (default {0})\n",
               32);
        Console.Write("\t-e\t\tOutput only encoded hash\n");
        Console.Write("\t-r\t\tOutput only the raw bytes of the hash\n");
        Console.Write("\t-v (10|13)\tArgon2 version (defaults to the most recent version, currently {0:X2})\n",
                (int)Argon2Version.ARGON2_VERSION_NUMBER);
        Console.Write("\t-h\t\tPrint {0} usage\n", cmd);
    }


    public static void PrintHex(byte[] bytes)
    {
        var sb = new StringBuilder();

        for (int i = 0; i < bytes.Length; i++)
            sb.AppendFormat("{0:x2}", bytes[i]);

        Console.WriteLine(sb.ToString());
    }

    public static byte[] ToByteArray(this string s)
    {
        return System.Text.Encoding.UTF8.GetBytes(s);
    }
}
