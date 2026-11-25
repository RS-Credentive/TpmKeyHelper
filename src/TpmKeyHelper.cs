using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Security.Principal;

namespace WindowsHelperFunctions
{
  [SupportedOSPlatform("windows")]
  public static class TpmKeyHelper
  {
    [UnmanagedCallersOnly(EntryPoint = "generate_tpm_key")]
    public static int GenerateTpmKey(
        nint aliasPtr, nint containerPtr, nint subjectDnPtr,
        nint errorBuffer, int errorBufferLength)
    {
      // Make sure we're being called from windows
      if (!OperatingSystem.IsWindows())
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, "This libarary will only work on Windows.");
        return -2;
      }

      // Check to see if we're running as an administrator.
      // If not, we can't access the Local Machine store and will fail to create a key that IIS can use.
      using WindowsIdentity identity = WindowsIdentity.GetCurrent();
      WindowsPrincipal principal = new WindowsPrincipal(identity);

      // Default to Local Machine store, but if we're not an admin, use Current User store instead
      var storeLocation = StoreLocation.LocalMachine;

      if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, "Running without Elevated Privileges. Creating Key in CurrentUser Store. Administrative Privileges are requried to create a key in the LocalMachine store for IIS.");
        storeLocation = StoreLocation.CurrentUser;
      }

      try
      {
        // Get the string values by dereferencing the pointers, dump immediately if they're not present
        string alias = Marshal.PtrToStringUTF8(aliasPtr)
            ?? throw new ArgumentNullException(nameof(aliasPtr));
        string containerName = Marshal.PtrToStringUTF8(containerPtr)
            ?? throw new ArgumentNullException(nameof(containerPtr));
        string subjectDn = Marshal.PtrToStringUTF8(subjectDnPtr)
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
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);

        // If we got here, we're successful
        return 0;
      }
      catch (ArgumentNullException ex)
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, $"Missing argument {ex.ParamName}");
        return -1;
      }
      catch (CryptographicException ex)
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, $"Cryptographic error: {ex.Message}");
        return -1;
      }
      catch (Exception ex)
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, $"Unexpected error: {ex.Message}");
        return -1;
      }
    }

  }
}
