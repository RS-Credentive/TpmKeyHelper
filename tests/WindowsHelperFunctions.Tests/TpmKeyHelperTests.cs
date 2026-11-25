using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WindowsHelperFunctions;

namespace WindowsHelperFunctions.Tests;

[SupportedOSPlatform("windows")]
public class TpmKeyHelperTests
{
    [Theory]
    [InlineData(0, "aliasPtr")]
    [InlineData(1, "containerPtr")]
    [InlineData(2, "subjectDnPtr")]
    public unsafe void GenerateTpmKey_ReturnsErrorWhenARequiredArgumentIsMissing(
        int missingArgumentIndex,
        string expectedParameterName)
    {
        nint alias = Marshal.StringToCoTaskMemUTF8("alias");
        nint container = Marshal.StringToCoTaskMemUTF8("container");
        nint subject = Marshal.StringToCoTaskMemUTF8("CN=Test");
        nint errorBuffer = Marshal.AllocHGlobal(256);

        try
        {
            Marshal.Copy(new byte[256], 0, errorBuffer, 256);

            delegate* unmanaged<nint, nint, nint, nint, int, int> generateTpmKey =
                &TpmKeyHelper.GenerateTpmKey;

            int result = generateTpmKey(
                missingArgumentIndex == 0 ? 0 : alias,
                missingArgumentIndex == 1 ? 0 : container,
                missingArgumentIndex == 2 ? 0 : subject,
                errorBuffer,
                256);

            Assert.Equal(-1, result);
            Assert.Equal(
                $"Missing argument {expectedParameterName}",
                Marshal.PtrToStringUTF8(errorBuffer));
        }
        finally
        {
            Marshal.FreeCoTaskMem(alias);
            Marshal.FreeCoTaskMem(container);
            Marshal.FreeCoTaskMem(subject);
            Marshal.FreeHGlobal(errorBuffer);
        }
    }
}
