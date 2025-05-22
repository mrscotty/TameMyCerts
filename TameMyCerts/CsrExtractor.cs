using System;
using System.IO;
using System.Formats.Asn1;

public static class CsrExtractor
{
    public static void ExtractPkcs10FromRaw(byte[] data, string outputPath)
    {
        for (int offset = 0; offset < data.Length - 1; offset++)
        {
            if (data[offset] != 0x30) // ASN.1 SEQUENCE
                continue;

            try
            {
                // Try parsing from this offset
                ReadOnlySpan<byte> slice = new ReadOnlySpan<byte>(data, offset);
                var reader = new AsnReader(slice, AsnEncodingRules.DER);

                // Read and store the full encoded value of the SEQUENCE
                ReadOnlyMemory<byte> pkcs10 = reader.ReadEncodedValue();

                // Convert to base64 PEM format
                string base64 = Convert.ToBase64String(pkcs10.ToArray(), Base64FormattingOptions.InsertLineBreaks);
                string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";

                File.WriteAllText(outputPath, pem);
                Console.WriteLine($"✅ PKCS#10 CSR extracted at offset {offset} and saved to: {outputPath}");
                return;
            }
            catch (AsnContentException)
            {
                // Not a valid DER-encoded SEQUENCE starting at this offset
            }
        }

        Console.WriteLine("❌ No valid PKCS#10 CSR found in the byte array.");
    }
}

