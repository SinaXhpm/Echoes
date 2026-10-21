using Foundation;

namespace Echoes.iOS;

/// <summary>
/// Keeps a file out of the device's iCloud and Finder backups (NSURLIsExcludedFromBackupKey). Hooked up as
/// AppStorage.ExcludeFromBackup by <see cref="Program"/>: SecretProtector uses it for the key file, which must not travel in
/// a backup next to the profile it opens.
/// </summary>
internal static class IosBackupExclusion
{
    public static void Exclude(string path)
    {
        using var url = NSUrl.FromFilename(path);
        if (!url.SetResource(NSUrl.IsExcludedFromBackupKey, NSNumber.FromBoolean(true), out NSError? error) && error is not null)
            throw new System.IO.IOException("Couldn't keep " + System.IO.Path.GetFileName(path) + " out of backups: " + error.LocalizedDescription);
    }
}
