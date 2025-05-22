using System;
using System.IO;
using System.Runtime.InteropServices;

public class CsrExtractor
{
    public static void ExtractPkcs10FromRaw(byte[] data, string outputPath)
    {
        for (int offset = 0; offset < data.Length; offset++)
        {
            if (data[offset] != 0x30) continue; // ASN.1 SEQUENCE

            if (TryValidatePkcs10(data, offset, out int length))
            {
                var csr = new byte[length];
                Array.Copy(data, offset, csr, 0, length);

                string base64 = Convert.ToBase64String(csr, Base64FormattingOptions.InsertLineBreaks);
                string pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64 + "\n-----END CERTIFICATE REQUEST-----";
                File.WriteAllText(outputPath, pem);

                Console.WriteLine($"✅ PKCS#10 CSR extracted and saved at offset {offset}");
                return;
            }
        }

        Console.WriteLine("❌ No PKCS#10 CSR found in the byte array.");
    }

    private static bool TryValidatePkcs10(byte[] data, int offset, out int length)
    {
        length = 0;

        try
        {
            byte[] slice = new byte[data.Length - offset];
            Array.Copy(data, offset, slice, 0, slice.Length);

            int size = 0;
            bool result = NativeMethods.CryptDecodeObjectEx(
                NativeMethods.X509_ASN_ENCODING,
                NativeMethods.X509_CERT_REQUEST_TO_BE_SIGNED,
                slice,
                slice.Length,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                ref size
            );

            if (result && size > 0)
            {
                length = size;
                return true;
            }
        }
        catch
        {
            // Swallow and continue
        }

        return false;
    }

    private static class NativeMethods
    {
        public const int X509_CERT_REQUEST_TO_BE_SIGNED = 0x0000000B;
        public const int X509_ASN_ENCODING = 0x00000001;

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptDecodeObjectEx(
            int dwCertEncodingType,
            int lpszStructType,
            byte[] pbEncoded,
            int cbEncoded,
            int dwFlags,
            IntPtr pDecodePara,
            IntPtr pvStructInfo,
            ref int pcbStructInfo
        );
    }
}

