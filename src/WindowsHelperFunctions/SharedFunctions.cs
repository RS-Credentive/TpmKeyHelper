using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WindowsHelperFunctions
{
  internal class SharedFunctions
  {
    protected internal static void WriteError(nint errorBuffer, int errorBufferLength, string errorMessage)
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
