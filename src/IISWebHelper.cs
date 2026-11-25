using Microsoft.Web.Administration;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace WindowsHelperFunctions
{
  [SupportedOSPlatform("windows")]
  public static class IISWebHelper
  {
    [UnmanagedCallersOnly(EntryPoint = "get_binding_buffer")]
    public static int GetBindingBuffer(
      nint outputBuffer, int outputBufferLength,
      nint errorBuffer, int errorBufferLength)
    {
      // Make sure we're being called from windows
      if (!OperatingSystem.IsWindows())
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, "This libarary will only work on Windows.");
        return -2;
      }

      String bindings;

      try
      {
        bindings = GetBindings();
      }
      catch (Exception ex)
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, ex.Message);
        return -1;
      }

      // Get the bytes so we can write to the buffer
      var bindingsBytes = Encoding.UTF8.GetBytes(bindings);

      if (bindingsBytes.Length != outputBufferLength)
      {
        SharedFunctions.WriteError(errorBuffer, errorBufferLength, "Output buffer is the wrong size.");
        return -1;
      }

      Marshal.Copy(bindingsBytes, 0, outputBuffer, outputBufferLength);
      return 0;

    }

    [UnmanagedCallersOnly(EntryPoint = "get_binding_buffer_size")]
    public static int GetBindingBufferSize()
    {
      try
      {
        return Encoding.UTF8.GetByteCount(GetBindings());
      }
      catch (Exception)
      {
        // If anything goes wrong, return -1 to indicate an error.
        return -1;
      }
    }

    public static String GetBindings()
    {
      using var stream = new MemoryStream();
      using (var writer = new Utf8JsonWriter(stream))
      {
        writer.WriteStartArray();

        var siteCollection = new ServerManager().Sites;
        
        foreach (Site site in siteCollection)
        {
          foreach (Binding binding in site.Bindings)
          {
            writer.WriteStartObject();
            writer.WriteString("siteName", site.Name);
            writer.WriteString("protocol", binding.Protocol);
            writer.WriteString("certificateStoreName", binding.CertificateStoreName);
            writer.WriteEndObject();
          }
        }
        writer.WriteEndArray();
      }

      return stream.ToString();
    }


  }
}

