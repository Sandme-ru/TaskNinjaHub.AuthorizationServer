using System.Security.Cryptography;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

public class Sha1HashProvider(byte[] validationKey) : HashProvider(validationKey, Sha1HashSize, Sha1KeySize)
{
    const int Sha1HashSize = 20;

    const int Sha1KeySize = 64;

    protected override HMAC CreateHasher(byte[] key) => new HMACSHA1(key);
}