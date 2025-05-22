using System;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class CsrExtractor
{
    /*
    // public static void ExtractPkcs10(string inputPath, string outputPath)
    public static void ExtractPkcs10(byte[] cmcBytes, string outputPath)
    {
        //byte[] cmcBytes = File.ReadAllBytes(inputPath);

        var outer = new AsnReader(cmcBytes, AsnEncodingRules.BER);
        var seq = outer.ReadSequence();

        while (seq.HasData)
        {
            var tag = seq.PeekTag();

            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
            {
                var content = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                var raw = content.ReadEncodedValue();

                var inner = new AsnReader(raw, AsnEncodingRules.BER);

                if (inner.PeekTag() == Asn1Tag.Sequence)
                {
                    byte[] pkcs10 = raw.ToArray();

                    string base64 = Convert.ToBase64String(pkcs10, Base64FormattingOptions.InsertLineBreaks);
                    string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                    File.WriteAllText(outputPath, pem);
                    Console.WriteLine("Extracted clean PKCS#10 CSR.");
                    return;
                }
            }

            seq.ReadEncodedValue(); // skip unneeded tag
        }

        Console.WriteLine("PKCS#10 CSR not found.");
    }
    */


    public static void ExtractPkcs10FromRaw(byte[] data, string outputPemPath)
    {

        for (int offset = 0; offset < data.Length; offset++)
        {
            try
            {
                // Try to parse a CertificationRequest from this offset
                ReadOnlySpan<byte> slice = new ReadOnlySpan<byte>(data, offset, data.Length - offset);
                var req = new Pkcs10CertificationRequest(slice);

                // If parsing succeeds, convert to PEM
                string base64 = Convert.ToBase64String(slice.Slice(0, req.RawData.Length), Base64FormattingOptions.InsertLineBreaks);
                string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                File.WriteAllText(outputPemPath, pem);

                Console.WriteLine($"OK: PKCS#10 CSR extracted at offset {offset} and saved to {outputPemPath}");
                return;
            }
            catch (CryptographicException)
            {
                // Not a valid PKCS#10 CSR at this offset — continue
            }
            catch (ArgumentOutOfRangeException)
            {
                break; // prevent slicing beyond array bounds
            }
        }

        Console.WriteLine("ERR:  No valid PKCS#10 CSR found in the input data.");
    }
    
}

