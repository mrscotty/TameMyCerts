using System;
using System.IO;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;

public class CsrExtractor
{
    public static void ExtractPkcs10FromRaw(byte[] data, string outputPemPath)
    {
        for (int offset = 0; offset < data.Length - 1; offset++)
        {
            if (data[offset] == 0x30) // SEQUENCE start
            {
                try
                {
                    var slice = new byte[data.Length - offset];
                    Array.Copy(data, offset, slice, 0, slice.Length);

                    var csr = new Pkcs10CertificationRequest(slice);

                    // Optional: validate the CSR
                    if (!csr.Verify())
                        continue;

                    using (var writer = new StreamWriter(outputPemPath))
                    {
                        var pemWriter = new PemWriter(writer);
                        pemWriter.WriteObject(csr);
                    }

                    Console.WriteLine($"✅ PKCS#10 CSR extracted at offset {offset} and saved to: {outputPemPath}");
                    return;
                }
                catch
                {
                    // Not a valid PKCS#10 at this offset
                    continue;
                }
            }
        }

        Console.WriteLine("❌ No valid PKCS#10 CSR found in the byte array.");
    }
}

