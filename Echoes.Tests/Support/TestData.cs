using System.Runtime.CompilerServices;
using Echoes.Helpers;

namespace Echoes.Tests.Support;

/// <summary>
/// Keeps every test away from the Echoes installed on this computer: before any test runs, the app's data folder (the
/// profile, the secret key, the vaults) is pointed at an empty folder beside the test program. A test that saves a
/// setting or seals a token then writes there, never into the user's own profile.
/// </summary>
internal static class TestData
{
    public static string Folder { get; } = Path.Combine(AppContext.BaseDirectory, "test-data");

    [ModuleInitializer]
    internal static void Isolate()
    {
        try { if (Directory.Exists(Folder)) Directory.Delete(Folder, recursive: true); }
        catch (IOException) { }   // a folder still held by a previous run: its files are replaced as they are written
        AppStorage.TestDir = Folder;
    }
}
