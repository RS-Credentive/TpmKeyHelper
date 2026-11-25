using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using WindowsHelperFunctions;

namespace WindowsHelperFunctions.Tests;

[SupportedOSPlatform("windows")]
public class IISWebHelperTests
{
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  private delegate int GetBindingBufferDelegate();

  [Fact]
  public void GetBindingBufferSize_ReturnsLengthOfGetBindings()
  {
    MethodInfo methodInfo = typeof(IISWebHelper).GetMethod("GetBindingBufferSize", BindingFlags.Public | BindingFlags.Static)
      ?? throw new InvalidOperationException("GetBindingBufferSize method not found.");
    IntPtr functionPointer = methodInfo.MethodHandle.GetFunctionPointer();

    var getBindingBufferSizeDelegate = Marshal.GetDelegateForFunctionPointer<GetBindingBufferDelegate>(functionPointer);

    int resultSize = getBindingBufferSizeDelegate();
    string result = IISWebHelper.GetBindings();

    Assert.Equal(Encoding.UTF8.GetByteCount(result), resultSize);
  }
}
