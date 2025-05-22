using System;
using System.Formats.Asn1;
using System.IO;

public class CsrExtractor
{
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
}

