using System.Diagnostics;

namespace Gts.AuthorizationServer.Models.LegacyAuthCookieCompat;

/// <summary>
/// Class FormsAuthenticationTicketHelper.
/// </summary>
internal static class FormsAuthenticationTicketHelper
{
    /// <summary>
    /// The current ticket serialized version
    /// </summary>
    private const byte CURRENT_TICKET_SERIALIZED_VERSION = 0x01;

    /// <summary>
    /// The maximum ticket length
    /// </summary>
    private const int MAX_TICKET_LENGTH = 4096;

    /// <summary>
    /// Resurrects a FormsAuthenticationTicket from its serialized blob representation.
    /// The input blob must be unsigned and unencrypted. This function returns null if
    /// the serialized ticket format is invalid. The caller must also verify that the
    /// ticket is still valid, as this method doesn't check expiration.
    /// </summary>
    /// <param name="serializedTicket">The serialized ticket.</param>
    /// <param name="serializedTicketLength">Length of the serialized ticket.</param>
    /// <returns>FormsAuthenticationTicket.</returns>
    public static FormsAuthenticationTicket Deserialize(byte[] serializedTicket, int serializedTicketLength)
    {
        try
        {
            using (var ticketBlobStream = new MemoryStream(serializedTicket))
            {
                using (var ticketReader = new SerializingBinaryReader(ticketBlobStream))
                {

                    // Step 1: Read the serialized format version number from the stream.
                    // Currently the only supported format is 0x01.
                    // LENGTH: 1 byte
                    byte serializedFormatVersion = ticketReader.ReadByte();
                    if (serializedFormatVersion != CURRENT_TICKET_SERIALIZED_VERSION)
                    {
                        return null; // unexpected value
                    }

                    // Step 2: Read the ticket version number from the stream.
                    // LENGTH: 1 byte
                    int ticketVersion = ticketReader.ReadByte();

                    // Step 3: Read the ticket issue date from the stream.
                    // LENGTH: 8 bytes
                    var ticketIssueDateUtcTicks = ticketReader.ReadInt64();
                    var ticketIssueDateUtc = new DateTime(ticketIssueDateUtcTicks, DateTimeKind.Utc);
                    var ticketIssueDateLocal = ticketIssueDateUtc.ToLocalTime();

                    // Step 4: Read the spacer from the stream.
                    // LENGTH: 1 byte
                    var spacer = ticketReader.ReadByte();
                    if (spacer != 0xfe)
                    {
                        return null; // unexpected value
                    }

                    // Step 5: Read the ticket expiration date from the stream.
                    // LENGTH: 8 bytes
                    var ticketExpirationDateUtcTicks = ticketReader.ReadInt64();
                    var ticketExpirationDateUtc = new DateTime(ticketExpirationDateUtcTicks, DateTimeKind.Utc);
                    var ticketExpirationDateLocal = ticketExpirationDateUtc.ToLocalTime();

                    // Step 6: Read the ticket persistence field from the stream.
                    // LENGTH: 1 byte
                    var ticketPersistenceFieldValue = ticketReader.ReadByte();
                    bool ticketIsPersistent;
                    switch (ticketPersistenceFieldValue)
                    {
                        case 0:
                            ticketIsPersistent = false;
                            break;
                        case 1:
                            ticketIsPersistent = true;
                            break;
                        default:
                            return null; // unexpected value
                    }

                    // Step 7: Read the ticket username from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    var ticketName = ticketReader.ReadBinaryString();

                    // Step 8: Read the ticket custom data from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    var ticketUserData = ticketReader.ReadBinaryString();

                    // Step 9: Read the ticket cookie path from the stream.
                    // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                    
                    //var ticketCookiePath = ticketReader.ReadBinaryString();
                    var ticketCookiePath = "/";

                    // Step 10: Read the footer from the stream.
                    // LENGTH: 1 byte
                    var footer = ticketReader.ReadByte();
                    if (footer != 0xff)
                    {
                        return null; // unexpected value
                    }

                    // Step 11: Verify that we have consumed the entire payload.
                    // We don't expect there to be any more information after the footer.
                    // The caller is responsible for telling us when the actual payload
                    // is finished, as he may have handed us a byte array that contains
                    // the payload plus signature as an optimization, and we don't want
                    // to misinterpet the signature as a continuation of the payload.
                    if (ticketBlobStream.Position != serializedTicketLength)
                    {
                        return null;
                    }

                    // Success.
                    return FromUtc(
                        ticketVersion /* version */,
                        ticketName /* name */,
                        ticketIssueDateUtc /* issueDateUtc */,
                        ticketExpirationDateUtc /* expirationUtc */,
                        ticketIsPersistent /* isPersistent */,
                        ticketUserData /* userData */,
                        ticketCookiePath /* cookiePath */);
                }
            }
        }
        catch
        {
            // If anything goes wrong while parsing the token, just treat the token as invalid.
            return null;
        }
    }

    /// <summary>
    /// Froms the UTC.
    /// </summary>
    /// <param name="version">The version.</param>
    /// <param name="name">The name.</param>
    /// <param name="issueDateUtc">The issue date UTC.</param>
    /// <param name="expirationUtc">The expiration UTC.</param>
    /// <param name="isPersistent">if set to <c>true</c> [is persistent].</param>
    /// <param name="userData">The user data.</param>
    /// <param name="cookiePath">The cookie path.</param>
    /// <returns>FormsAuthenticationTicket.</returns>
    internal static FormsAuthenticationTicket FromUtc(int version, string name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, string userData, string cookiePath)
    {
        var ticket = new FormsAuthenticationTicket(version, name, issueDateUtc.ToLocalTime(), expirationUtc.ToLocalTime(), isPersistent, userData, cookiePath);
        return ticket;
    }

    /// <summary>
    /// Turns a FormsAuthenticationTicket into a serialized blob.
    /// The resulting blob is not encrypted or signed.
    /// </summary>
    /// <param name="ticket">The ticket.</param>
    /// <returns>System.Byte[].</returns>
    public static byte[] Serialize(FormsAuthenticationTicket ticket)
    {
        using (var ticketBlobStream = new MemoryStream())
        {
            using (var ticketWriter = new SerializingBinaryWriter(ticketBlobStream))
            {
                // SECURITY NOTE:
                // Earlier versions of the serializer (Framework20 / Framework40) wrote out a
                // random 8-byte header as the first part of the payload. This random header
                // was used as an IV when the ticket was encrypted, since the early encryption
                // routines didn't automatically append an IV when encrypting data. However,
                // the MSRC 10405 (Pythia) patch causes all of our crypto routines to use an
                // IV automatically, so there's no need for us to include a random IV in the
                // serialized stream any longer. We can just write out only the data, and the
                // crypto routines will do the right thing.

                // Step 1: Write the ticket serialized format version number (currently 0x01) to the stream.
                // LENGTH: 1 byte
                ticketWriter.Write(CURRENT_TICKET_SERIALIZED_VERSION);

                // Step 2: Write the ticket version number to the stream.
                // This is the developer-specified FormsAuthenticationTicket.Version property,
                // which is just ticket metadata. Technically it should be stored as a 32-bit
                // integer instead of just a byte, but we have historically been storing it
                // as just a single byte forever and nobody has complained.
                // LENGTH: 1 byte
                ticketWriter.Write((byte)ticket.Version);

                // Step 3: Write the ticket issue date to the stream.
                // We store this value as UTC ticks. We can't use DateTime.ToBinary() since it
                // isn't compatible with .NET v1.1.
                // LENGTH: 8 bytes (64-bit little-endian in payload)
                ticketWriter.Write(ticket.IssueDate.ToUniversalTime().Ticks);

                // Step 4: Write a one-byte spacer (0xfe) to the stream.
                // One of the old ticket formats (Framework40) expects the unencrypted payload
                // to contain 0x000000 (3 null bytes) beginning at position 9 in the stream.
                // Since we're currently at offset 10 in the serialized stream, we can take
                // this opportunity to purposely inject a non-null byte at this offset, which
                // intentionally breaks compatibility with Framework40 mode.
                // LENGTH: 1 byte
                Debug.Assert(ticketBlobStream.Position == 10, "Critical that we be at position 10 in the stream at this point.");
                ticketWriter.Write((byte)0xfe);

                // Step 5: Write the ticket expiration date to the stream.
                // We store this value as UTC ticks.
                // LENGTH: 8 bytes (64-bit little endian in payload)
                ticketWriter.Write(ticket.Expiration.ToUniversalTime().Ticks);

                // Step 6: Write the ticket persistence field to the stream.
                // LENGTH: 1 byte
                ticketWriter.Write(ticket.IsPersistent);

                // Step 7: Write the ticket username to the stream.
                // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                ticketWriter.WriteBinaryString(ticket.Name);

                // Step 8: Write the ticket custom data to the stream.
                // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                ticketWriter.WriteBinaryString(ticket.UserData);

                // Step 9: Write the ticket cookie path to the stream.
                // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                ticketWriter.WriteBinaryString(ticket.CookiePath);

                // Step 10: Write a one-byte footer (0xff) to the stream.
                // One of the old FormsAuthenticationTicket formats (Framework20) requires
                // that the payload end in 0x0000 (U+0000). By making the very last byte
                // of this format non-null, we can guarantee a compatiblity break between
                // this format and Framework20.
                // LENGTH: 1 byte
                ticketWriter.Write((byte)0xff);

                // Finished.
                return ticketBlobStream.ToArray();
            }
        }
    }

    /// <summary>
    /// Class SerializingBinaryReader. This class cannot be inherited.
    /// Implements the <see cref="System.IO.BinaryReader" />
    /// </summary>
    /// <seealso cref="System.IO.BinaryReader" />
    private sealed class SerializingBinaryReader : BinaryReader
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SerializingBinaryReader"/> class.
        /// </summary>
        /// <param name="input">The input stream.</param>
        public SerializingBinaryReader(Stream input)
            : base(input)
        {
        }

        /// <summary>
        /// Reads the binary string.
        /// </summary>
        /// <returns>System.String.</returns>
        public string ReadBinaryString()
        {
            var charCount = Read7BitEncodedInt();
            var bytes = ReadBytes(charCount * 2);

            var chars = new char[charCount];
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
            }

            return new string(chars);
        }

        /// <summary>
        /// Reads a string from the current stream. The string is prefixed with the length, encoded as an integer seven bits at a time.
        /// </summary>
        /// <returns>The string being read.</returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override string ReadString()
        {
            // should never call this method since it will produce wrong results
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// This is a special BinaryWriter which serializes strings in a way that is
    /// entirely round-trippable. For example, the string "\ud800" is a valid .NET
    /// Framework string, but since U+D800 is an unpaired Unicode surrogate the
    /// built-in Encoding types will not round-trip it. Strings are serialized as a
    /// 7-bit character count (not byte count!) followed by a UTF-16LE payload.
    /// </summary>
    private sealed class SerializingBinaryWriter : BinaryWriter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SerializingBinaryWriter"/> class.
        /// </summary>
        /// <param name="output">The output stream.</param>
        public SerializingBinaryWriter(Stream output)
            : base(output)
        {
        }

        /// <summary>
        /// Writes a length-prefixed string to this stream in the current encoding of the <see cref="T:System.IO.BinaryWriter" />, and advances the current position of the stream in accordance with the encoding used and the specific characters being written to the stream.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <exception cref="System.NotImplementedException"></exception>
        public override void Write(string value)
        {
            // should never call this method since it will produce wrong results
            throw new NotImplementedException();
        }

        /// <summary>
        /// Writes the binary string.
        /// </summary>
        /// <param name="value">The value.</param>
        public void WriteBinaryString(string value)
        {
            var bytes = new byte[value.Length * 2];
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                bytes[2 * i] = (byte)c;
                bytes[2 * i + 1] = (byte)(c >> 8);
            }

            Write7BitEncodedInt(value.Length);
            Write(bytes);
        }
    }

}