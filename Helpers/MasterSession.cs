using System;

namespace Echoes.Helpers;

/// <summary>
/// One shared master password for the whole app, held in memory only (never persisted).
/// Signing in on the SYNC tab, or unlocking Notes / Cloudflare, all funnel through here so
/// the user types a single credential once and the other locked areas open automatically.
///
/// <para>The password itself is the same string used to (a) authenticate to the submarine
/// backend and (b) derive the local Notes / Cloudflare vault keys — matching the app's
/// "one master credential" model. It lives only for the session and is wiped on lock.</para>
/// </summary>
public static class MasterSession
{
    private static string _password = string.Empty;

    /// <summary>The active master password, or empty when locked.</summary>
    public static string Password => _password;

    /// <summary>True while a master password is held (i.e. the app is unlocked).</summary>
    public static bool IsSet => _password.Length > 0;

    /// <summary>Raised when the shared password is set or cleared. Handlers run synchronously;
    /// subscribers should marshal to the UI thread themselves if they touch bound state.</summary>
    public static event Action? Changed;

    /// <summary>Adopt <paramref name="password"/> as the shared master. No-op if empty or unchanged
    /// (so auto-unlock echoing the same password back doesn't loop).</summary>
    public static void Set(string password)
    {
        if (string.IsNullOrEmpty(password) || password == _password) return;
        _password = password;
        Changed?.Invoke();
    }

    /// <summary>Wipe the shared password (locks every area that follows the session).</summary>
    public static void Clear()
    {
        if (_password.Length == 0) return;
        _password = string.Empty;
        Changed?.Invoke();
    }

    /// <summary>Raised after a backup restore overwrote the on-disk vaults. Live areas must DROP their
    /// stale in-memory decrypted state WITHOUT re-saving (a save would clobber the just-restored file)
    /// and lock, forcing a re-unlock that reads the restored data. Handlers marshal to the UI thread.</summary>
    public static event Action? RestoreApplied;

    /// <summary>Signal a completed backup restore. Wipes the shared password directly (no <see cref="Changed"/>
    /// event, so nothing auto-re-unlocks with the old key or triggers a clobbering save) then fires
    /// <see cref="RestoreApplied"/> so live vault VMs discard-and-lock without saving.</summary>
    public static void NotifyRestoreApplied()
    {
        _password = string.Empty;
        RestoreApplied?.Invoke();
    }
}
