using Argon2;
using Argon2.Core;
using Argon2.Enums;
using System.Diagnostics;

/*
Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
Base64-encoded hash string
@out output array with at least 32 bytes allocated
@pwd NULL-terminated string, presumably from args[]
@salt salt array
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
@type Argon2 type we want to run
@encoded_only display only the encoded hash
@raw_only display only the hexadecimal of the hash
@version Argon2 version
*/
void Run(
    int outlen, 
    string pwd,
    string salt,
    uint t_cost,
    uint m_cost,
    uint threads,
    Argon2Type type,
    bool encoded_only,
    bool raw_only,
    Argon2Version version)
{
    Argon2_ErrorCodes result;
    Stopwatch s1 = Stopwatch.StartNew();

    if (pwd is null) throw new Exception("password missing");

    if (salt is null) throw new Exception("salt missing");
    
    result = Argon2.Core.Argon2.Argon2Hash(
        t_cost,
        m_cost,
        threads,
        System.Text.Encoding.UTF8.GetBytes(pwd),
        System.Text.Encoding.UTF8.GetBytes(salt),
        (uint)outlen,
        type, version,
        out var context);
    
    if (result != Argon2_ErrorCodes.ARGON2_OK)
        Console.WriteLine(result.GetErrorMessage());

    s1.Stop();

    Encoding.EncodeString(context, type, out string encoded);

    if (encoded_only)
        Console.WriteLine(encoded);

    if (raw_only)
        Helpers.PrintHex(context.Out);

    if (encoded_only || raw_only)
        return;

    Console.Write("Hash:\t\t");
    Helpers.PrintHex(context.Out);

    Console.WriteLine("Encoded:\t{0}", encoded);

    Console.WriteLine("%{0:F3} seconds", s1.ElapsedMilliseconds / 1000);
    
    result = Argon2.Core.Argon2.Argon2Verify(encoded, System.Text.Encoding.UTF8.GetBytes(pwd), type);
    if (result != Argon2_ErrorCodes.ARGON2_OK)
        Console.WriteLine(result.GetErrorMessage());
    
    Console.WriteLine("Verification OK");
}

int outlen = 32;
uint m_cost = 1 << 12;
uint t_cost = 3;
uint threads = 1;
Argon2Type type = Argon2Type.I; /* Argon2i is the default type */
bool m_cost_specified = false;
bool encoded_only = false;
bool raw_only = false;
Argon2Version version = Argon2Version.ARGON2_VERSION_NUMBER;
int i;

if (args.Length < 1)
{
    Helpers.PrintHelp("argon2");
    return (int)Argon2_ErrorCodes.ARGON2_MISSING_ARGS;
}
else if (args.Length >= 1 && !args[0].Equals("-h"))
{
    Helpers.PrintHelp(args[0]);
    return 1;
}

/* get password from stdin */
string pwd = Console.ReadLine() ?? string.Empty;
if (pwd.Length < 1)
{
    Console.WriteLine("no password read");
    return -1;
}
if (pwd.Length >= 128)
{
    Console.WriteLine("Provided password longer than supported in command line utility");
    return -1;
}

var salt = args[0];

/* parse options */
for (i = 1; i < args.Length; i++)
{
    string a = args[i];
    if (a == "-h")
    {
        Helpers.PrintHelp("argon2");
        return 1;
    }
    else if (a == "-m")
    {
        if (m_cost_specified)
        {
            Console.WriteLine("-m or -k can only be used once");
        }
        m_cost_specified = true;
        if (i < args.Length - 1)
        {
            i++;
            string mValue = args[i];
            if (!int.TryParse(mValue, out int mInt) || mInt > Consts.ARGON2_MAX_MEMORY_BITS)
            {
                Console.WriteLine("bad numeric input for -m");
            }
            
            m_cost = Math.Min(1U << mInt, uint.MaxValue);
            if (m_cost > Consts.ARGON2_MAX_MEMORY)
                Console.WriteLine("m_cost overflow");

            continue;
        }
        else
        {
            Console.WriteLine("missing -m argument");
        }
    }
    else if (a == "-k")
    {
        if (m_cost_specified)
        {
            Console.WriteLine("-m or -k can only be used once");
        }
        m_cost_specified = true;
        if (i < args.Length - 1)
        {
            i++;
            string kValue = args[i];
            if (!int.TryParse(kValue, out int kInt) || kInt == uint.MinValue || kInt == 0)
            {
                Console.WriteLine("bad numeric input for -k");
            }

            m_cost = Math.Min(1U << kInt, uint.MaxValue);
            if (m_cost > Consts.ARGON2_MAX_MEMORY)
                Console.WriteLine("m_cost overflow");

            continue;
        }
        else
        {
            Console.WriteLine("missing -k argument");
        }
    }
    else if (a == "-t")
    {
        if (i < args.Length - 1)
        {
            i++;
            string tValue = args[i];
            if (!int.TryParse(tValue, out int tInt) || tInt == uint.MinValue)
            {
                Console.WriteLine("bad numeric input for -t");
            }
            t_cost = (uint)tInt;
            continue;
        }
        else
        {
            Console.WriteLine("missing -t argument");
        }
    }
    else if (a == "-p")
    {
        if (i < args.Length - 1)
        {
            i++;
            string pValue = args[i];
            if (!int.TryParse(pValue, out int pInt) || pInt > Consts.ARGON2_MAX_LANES)
            {
                Console.WriteLine("bad numeric input for -p");
            }
            threads = (uint)pInt;
            continue;
        }
        else
        {
            Console.WriteLine("missing -p argument");
        }
    }
    else if (a == "-l")
    {
        if (i < args.Length - 1)
        {
            i++;
            string lValue = args[i];
            if (!int.TryParse(lValue, out int lInt))
            {
                Console.WriteLine("bad numeric input for -p");
            }
            outlen = lInt;
            continue;
        }
        else
        {
            Console.WriteLine("missing -l argument");
        }
    }
    else if (a == "-i")
    {
        type = Argon2Type.I;
    }
    else if (a == "-d")
    {
        type = Argon2Type.D;
    }
    else if (a == "-id")
    {
        type = Argon2Type.ID;
    }
    else if (a == "-e")
    {
        encoded_only = true;
    }
    else if (a == "-r")
    {
        raw_only = true;
    }
    else if (a == "-v")
    {
        if (i < args.Length - 1)
        {
            i++;
            if (args[i] == "10")
                version = Argon2Version.ARGON2_VERSION_10;
            else if (args[i] == "13")
                version = Argon2Version.ARGON2_VERSION_13;
            else
                Console.WriteLine("invalid Argon2 version");
        }
        else
        {
            Console.WriteLine("missing -v argument");
        }
    }
    else
    {
        Console.WriteLine("unknown argument");
    }
}

if (encoded_only && raw_only)
    Console.WriteLine("cannot provide both -e and -r");

if (!encoded_only && !raw_only)
{
    Console.WriteLine("Type:\t\t{0}", type.Argon2Type2string(true));
    Console.WriteLine("Iterations:\t{0}", t_cost);
    Console.WriteLine("Memory:\t\t{0} KiB", m_cost);
    Console.WriteLine("Parallelism:\t{0}", threads);
}

Run(outlen, pwd, salt, t_cost, m_cost, threads, type, encoded_only, raw_only, version);

return 0;