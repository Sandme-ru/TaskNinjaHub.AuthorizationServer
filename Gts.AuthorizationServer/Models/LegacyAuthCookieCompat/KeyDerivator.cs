using System.Security.Cryptography;
using System.Text;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

static class KeyDerivator
{
    public static readonly UTF8Encoding SecureUTF8Encoding = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static byte[] DeriveKey(byte[] keyDerivationKey, CompatibilityMode compatibilityMode)
    {
        if (compatibilityMode == CompatibilityMode.Framework20SP2)
        {
            return keyDerivationKey;
        }

        using (var hmac = new HMACSHA512(keyDerivationKey))
        {
            byte[] label, context;
            GetKeyDerivationParameters(out label, out context);

            byte[] derivedKey = DeriveKeyImpl(hmac, label, context, keyDerivationKey.Length * 8);
            return derivedKey;
        }
    }

    private static void GetKeyDerivationParameters(out byte[] label, out byte[] context)
    {
        label = SecureUTF8Encoding.GetBytes("FormsAuthentication.Ticket");
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, SecureUTF8Encoding))
        {
            context = stream.ToArray();
        }
    }

    private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
    {
        checked
        {
            var labelLength = (label != null) ? label.Length : 0;
            var contextLength = (context != null) ? context.Length : 0;
            var buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

            if (labelLength != 0)
            {
                Buffer.BlockCopy(label, 0, buffer, 4, labelLength);
            }
            if (contextLength != 0)
            {
                Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength);
            }
            WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, buffer, 5 + labelLength + contextLength);

            var numBytesWritten = 0;
            var numBytesRemaining = keyLengthInBits / 8;
            var output = new byte[numBytesRemaining];

            for (uint i = 1; numBytesRemaining > 0; i++)
            {
                WriteUInt32ToByteArrayBigEndian(i, buffer, 0);
                var K_i = hmac.ComputeHash(buffer);

                var numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
                Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
                numBytesWritten += numBytesToCopy;
                numBytesRemaining -= numBytesToCopy;
            }

            return output;
        }
    }

    private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
    {
        buffer[offset + 0] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)(value);
    }
}