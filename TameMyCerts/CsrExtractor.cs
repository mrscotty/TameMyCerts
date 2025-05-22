using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;

public class CsrExtractor
{
    public static void ExtractPkcs10FromRaw(byte[] data, string outputPath)
    {
        for (int offset = 0; offset < data.Length; offset++)
        {
            if (data[offset] != 0x30) continue; // Only try if tag is ASN.1 SEQUENCE

            try
            {
                // Try parsing DER structure from this offset
                ReadOnlySpan<byte> slice = new ReadOnlySpan<byte>(data, offset);
                var reader = new AsnReader(slice, AsnEncodingRules.DER);

                // Read full CertificationRequest (SEQUENCE)
                var encodedCsr = reader.PeekEncodedValue().ToArray();

                // Attempt to load it as a PKCS#10 Certification Request
                var request = CertificateRequest.CreateFromSigningRequest(encodedCsr);

                // If we get here, parsing succeeded — write PEM
                string base64 = Convert.ToBase64String(encodedCsr, Base64FormattingOptions.InsertLineBreaks);
                string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                File.WriteAllText(outputPath, pem);

                Console.WriteLine($"✅ PKCS#10 CSR extracted and saved at offset {offset} to: {outputPath}");
                return;
            }
            catch
            {
                // Ignore and try next offset
            }
        }

        Console.WriteLine("❌ No valid PKCS#10 CSR found in the byte array.");
    }
}

