namespace Argon2.Interfaces;

using Argon2.Core;

internal interface IFillSegment
{
    abstract static void FillSegment(in Argon2Instance instance, Argon2Position position);
}
