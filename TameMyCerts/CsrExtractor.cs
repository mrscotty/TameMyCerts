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
            if (data[offset] == 0x30) // ASN.1 SEQUENCE
            {
                try
                {
                    var slice = new ReadOnlySpan<byte>(data, offset, data.Length - offset);
                    var csr = new CertificateRequest(slice, out int bytesRead);

                    byte[] csrBytes = slice.Slice(0, bytesRead).ToArray();
                    string base64 = Convert.ToBase64String(csrBytes, Base64FormattingOptions.InsertLineBreaks);
                    string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                    File.WriteAllText(outputPemPath, pem);

                    Console.WriteLine($"✅ Found PKCS#10 CSR at offset {offset}. Saved to: {outputPemPath}");
                    return;
                }
                catch (Exception)
                {
                    // Not a valid CSR here — keep scanning
                }
            }
        }

        Console.WriteLine("ERR:  No valid PKCS#10 CSR found in the input data.");
    }
    
}

