using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TpmKeyHelper
{
    [SupportedOSPlatform("windows")]
    public static class NativeExports
    {
        [UnmanagedCallersOnly(EntryPoint = "generate_tpm_key")]
        public static int GenerateTpmKey(
            nint aliasPtr, nint containerPtr, nint subjectDnPtr,
            nint errorBuffer, int errorBufferLength)
        {
            // Make sure we're being called from windows
            if (!OperatingSystem.IsWindows())
            {
                WriteError(errorBuffer, errorBufferLength, "This libarary will only work on Windows.");
                return -2;
            }


            try
            {
                // Get the string values by dereferencing the pointers, dump immediately if they're not present
                string alias = Marshal.PtrToStringUni(aliasPtr)
                    ?? throw new ArgumentNullException(nameof(aliasPtr));
                string containerName = Marshal.PtrToStringUni(containerPtr)
                    ?? throw new ArgumentNullException(nameof(containerPtr));
                string subjectDn = Marshal.PtrToStringUni(subjectDnPtr)
                    ?? throw new ArgumentNullException(nameof(subjectDnPtr));

                // Create a key
                var keyParams = new CngKeyCreationParameters
                {
                    Provider = CngProvider.MicrosoftPlatformCryptoProvider,
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                    ExportPolicy = CngExportPolicies.None
                };
                keyParams.Parameters.Add
                    (new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

                using CngKey cngKey = CngKey.Create(CngAlgorithm.Rsa, containerName, keyParams);
                using RSA rsa = new RSACng(cngKey);

                // Generate a self-signed certificate so the key can be stored and accessed by Java
                var request = new CertificateRequest
                    (subjectDn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Lifetime is only 1 day, since it should be replaced with an ACME cert very quickly
                using X509Certificate2 cert = request.CreateSelfSigned
                    (DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

                // Set friendly name since Java will use it as the keystore alias
                cert.FriendlyName = alias;

                // Store the cert in the Local Machine store. This is the right choice for IIS, but will require admin privileges
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                // If we got here, we're successful
                return 0;
            }
            catch(ArgumentNullException ex)
            {
                WriteError(errorBuffer, errorBufferLength, $"Missing argument {ex.ParamName}");
                return -1;
            }
            catch (CryptographicException ex)
            {
                WriteError(errorBuffer, errorBufferLength, $"Cryptographic error: {ex.Message}");
                return -1;
            }
            catch (Exception ex)
            {
                WriteError(errorBuffer, errorBufferLength, $"Unexpected error: {ex.Message}");
                return -1;
            }
        }

        private static void WriteError(nint errorBuffer, int errorBufferLength,  string errorMessage)
        {
            if (errorBuffer == 0 || errorBufferLength < 1)
            {
                return;
            }

            // How long is the message
            var utfErrorMessageBytes = Encoding.UTF8.GetBytes(errorMessage);

            // Which is shorter, the message or the buffer?
            int errorLength = Math.Min(utfErrorMessageBytes.Length, errorBufferLength - 1);

            // Copy as much of the massage as possible to the error buffer
            Marshal.Copy(utfErrorMessageBytes, 0, errorBuffer, errorLength);

            // Zero terminate the string
            Marshal.WriteByte(errorBuffer, errorLength, 0);
        }
    }
}
