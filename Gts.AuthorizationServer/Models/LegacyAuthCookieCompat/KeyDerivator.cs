using System.Security.Cryptography;
using System.Text;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class KeyDerivator.
/// </summary>
static class KeyDerivator
{
    /// <summary>
    /// The secure ut f8 encoding
    /// </summary>
    public static readonly UTF8Encoding SecureUTF8Encoding = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Derives the key.
    /// </summary>
    /// <param name="keyDerivationKey">The key derivation key.</param>
    /// <param name="compatibilityMode">The compatibility mode.</param>
    /// <returns>System.Byte[].</returns>
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

    /// <summary>
    /// Gets the key derivation parameters.
    /// </summary>
    /// <param name="label">The label.</param>
    /// <param name="context">The context.</param>
    private static void GetKeyDerivationParameters(out byte[] label, out byte[] context)
    {
        label = SecureUTF8Encoding.GetBytes("FormsAuthentication.Ticket");
        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, SecureUTF8Encoding))
        {
            context = stream.ToArray();
        }
    }

    /// <summary>
    /// Derives the key implementation.
    /// </summary>
    /// <param name="hmac">The hmac.</param>
    /// <param name="label">The label.</param>
    /// <param name="context">The context.</param>
    /// <param name="keyLengthInBits">The key length in bits.</param>
    /// <returns>System.Byte[].</returns>
    private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
    {
        checked
        {
            var labelLength = (label != null) ? label.Length : 0;
            var contextLength = (context != null) ? context.Length : 0;
            var buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

            if (labelLength != 0)
            {
                Buffer.BlockCopy(label, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
            }
            if (contextLength != 0)
            {
                Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
            }
            WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, buffer, 5 + labelLength + contextLength); // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

            // Initialization

            var numBytesWritten = 0;
            var numBytesRemaining = keyLengthInBits / 8;
            var output = new byte[numBytesRemaining];

            // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.

            for (uint i = 1; numBytesRemaining > 0; i++)
            {
                WriteUInt32ToByteArrayBigEndian(i, buffer, 0); // set the first 32 bits of the buffer to be the current iteration value
                var K_i = hmac.ComputeHash(buffer);

                // copy the leftmost bits of K_i into the output buffer
                var numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
                Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
                numBytesWritten += numBytesToCopy;
                numBytesRemaining -= numBytesToCopy;
            }

            // finished
            return output;
        }
    }

    /// <summary>
    /// Writes the u int32 to byte array big endian.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <param name="buffer">The buffer.</param>
    /// <param name="offset">The offset.</param>
    private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
    {
        buffer[offset + 0] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)(value);
    }
}