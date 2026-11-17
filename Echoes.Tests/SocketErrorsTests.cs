using System;
using System.IO;
using System.Security.Authentication;
using Echoes.Helpers;
using Xunit;

namespace Echoes.Tests;

/// <summary>How a failed TLS handshake is put into words, from what each platform's TLS stack says.</summary>
public class SocketErrorsTests
{
    [Theory]
    // Android / .NET's managed reader, when the bytes that come back aren't TLS records (seen on a phone whose network
    // answers DoT to 1.1.1.1 in its place)
    [InlineData("Cannot determine the frame size or a corrupted frame was received.")]
    // OpenSSL (Linux) and SChannel (Windows) for the same thing
    [InlineData("error:0A00010B:SSL routines::wrong version number")]
    [InlineData("The message received was unexpected or badly formatted.")]
    public void Bytes_that_are_not_TLS_are_said_to_be_so_and_a_filter_is_named_as_a_cause(string platformMessage)
    {
        var ex = new AuthenticationException("Authentication failed, see inner exception.", new IOException(platformMessage));
        string text = SocketErrors.TlsFailure(ex, "1.1.1.1");
        Assert.StartsWith("1.1.1.1 isn't speaking TLS", text, StringComparison.Ordinal);   // DoctorTls / TlsInspector look for this
        Assert.Contains("filter on the network", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_connection_closed_mid_handshake_is_not_called_a_non_TLS_answer()
    {
        var ex = new AuthenticationException("Authentication failed", new IOException("Received an unexpected EOF or 0 bytes from the transport stream."));
        string text = SocketErrors.TlsFailure(ex, "example.org");
        Assert.DoesNotContain("isn't speaking TLS", text, StringComparison.Ordinal);
        Assert.Contains("closed the connection", text, StringComparison.Ordinal);
    }
}
