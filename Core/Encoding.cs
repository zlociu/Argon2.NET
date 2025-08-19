namespace Argon2.Core;

using global::Argon2.Enums;
using System;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// The code below applies the following format: <br/>
/// <c> $argon2&lt;T&gt;[$v=&lt;num&gt;]$m=&lt;num&gt;,t=&lt;num&gt;,p=&lt;num&gt;$&lt;bin&gt;$&lt;bin&gt; </c> <br/>
/// where:
/// <list type="bullet">
/// <item>
/// <term>&lt;T&gt;</term> 'd', 'id', or 'i',
/// </item>
/// <item>
/// <term>&lt;num&gt;</term> a decimal integer (positive, fits in an 'ulong'),
/// </item>
/// <item>
/// <term>&lt;bin&gt;</term> Base64-encoded data(no '=' padding characters, no newline or whitespace).
/// </item>
/// </list>
/// The last two binary chunks(encoded in Base64) are, in that order,
/// the salt and the output. Both are required. The binary salt length and the output length must be in the allowed ranges defined in <see cref="Consts"/>.
/// The ctx struct must contain buffers large enough to hold the salt and pwd when it is fed into <see cref="DecodeString(string, Enums.Argon2Type, Argon2Context)"/>.
/// </summary>
public class Encoding
{
    private static string PadBase64(string input)
    {
        var len = input.Length & 3;
        return input + (len switch { 3 => "=", 2 => "==", _ => "" });
    }

    public static Argon2_ErrorCodes DecodeString(string str, Argon2Type type, Argon2Context ctx)
    {
        var result = Argon2Regex.Argon2Pattern().Match(str);

        if (!result.Success)
            return Argon2_ErrorCodes.ARGON2_DECODING_FAIL;

        Enum.TryParse<Argon2Type>(result.Groups["type"].Value, true, out var parsedType);

        if (type != parsedType)
            return Argon2_ErrorCodes.ARGON2_DECODING_FAIL;

        ctx.version = Argon2Version.ARGON2_VERSION_10; // default

        if (uint.TryParse(result.Groups["version"].Value, out uint ver))
            ctx.version = (Argon2Version)ver;
        
        ctx.m_cost = uint.Parse(result.Groups["m_cost"].Value);
        ctx.t_cost = uint.Parse(result.Groups["t_cost"].Value);
        ctx.lanes = uint.Parse(result.Groups["lanes"].Value);
        ctx.threads = ctx.lanes;

        ctx.salt = Convert.FromBase64String(PadBase64(result.Groups["salt"].Value));
        ctx._out = Convert.FromBase64String(PadBase64(result.Groups["out"].Value));

        ctx.secret = [];
        ctx.ad = [];
        ctx.flags = Consts.ARGON2_DEFAULT_FLAGS;

        /* On return, must have valid context */
        var validation_result = ctx.ValidateInputs();
        if (validation_result != Argon2_ErrorCodes.ARGON2_OK)
            return validation_result;

        return Argon2_ErrorCodes.ARGON2_OK;
    }

    /// <summary>
    /// encode an Argon2 hash string into the provided buffer.
    /// </summary>
    /// <returns>on success, ARGON2_OK is returned</returns>
    public static Argon2_ErrorCodes EncodeString(Argon2Context ctx, Argon2Type type, out string dst)
    {
        var sb = new StringBuilder();
        sb.Append('$');
        sb.Append(type.Argon2Type2string(false));
        sb.Append("$v=");
        sb.Append((uint)ctx.version);
        sb.Append("$m=");
        sb.Append(ctx.m_cost);
        sb.Append(",t=");
        sb.Append(ctx.t_cost);
        sb.Append(",p=");
        sb.Append(ctx.lanes);

        sb.Append('$');
        sb.Append(Convert.ToBase64String(ctx.salt).TrimEnd('='));
        sb.Append('$');
        sb.Append(Convert.ToBase64String(ctx._out).TrimEnd('='));

        dst = sb.ToString();

        return Argon2_ErrorCodes.ARGON2_OK;
    }
}

internal partial class Argon2Regex
{
    [GeneratedRegex(@"\$argon2(?<type>i|d|id)(\$v=(?<version>[0-9]+))?\$m=(?<m_cost>[0-9]+),t=(?<t_cost>[0-9]+),p=(?<lanes>[0-9])+\$(?<salt>[/A-Za-z0-9\+]+)\$(?<out>[/A-Za-z0-9\+]+)")]
    public static partial Regex Argon2Pattern();
}