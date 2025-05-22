using System;
using System.Formats.Asn1;
using System.IO;

public class CsrExtractor
{
    public static void ExtractPkcs10FromRaw(byte[] data, string outputPath)
    {
        for (int offset = 0; offset < data.Length - 1; offset++)
        {
            if (data[offset] != 0x30) // ASN.1 SEQUENCE
                continue;

            try
            {
                ReadOnlySpan<byte> slice = new ReadOnlySpan<byte>(data, offset);
                var reader = new AsnReader(slice, AsnEncodingRules.DER);

                // Try to read the whole SEQUENCE as a raw blob
                var pkcs10 = reader.ReadEncodedValue().ToArray();

                // PEM encode it
                string base64 = Convert.ToBase64String(pkcs10, Base64FormattingOptions.InsertLineBreaks);
                string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                File.WriteAllText(outputPath, pem);

                Console.WriteLine($"✅ PKCS#10 CSR extracted at offset {offset} and saved to: {outputPath}");
                return;
            }
            catch (AsnContentException)
            {
                // Not a valid SEQUENCE here — continue
            }
        }

        Console.WriteLine("❌ No valid PKCS#10 CSR found in the byte array.");
    }
}

