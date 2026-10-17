using System;
using System.Threading;

namespace Echoes.Helpers;

/// <summary>
/// One shared master password for the whole app, held in memory only (never persisted).
/// Unlocking Notes or Cloudflare funnels through here so the user types a single credential
/// once and the other locked areas open automatically.
///
/// <para>The password derives the local Notes / Cloudflare vault keys — the app's "one master credential" model. It is
/// kept in a pinned char buffer (see <see cref="SecureMemory"/>), never as a string: LOCK, a restore or a process exit
/// zeroes it in place. Callers get a <see cref="CopyPassword">private copy</see> per unlock attempt and zero that too.</para>
/// </summary>
public static class MasterSession
{
    private static readonly object Gate = new();
    private static char[] _password = Array.Empty<char>();
    private static int _epoch;

    /// <summary>Changes, synchronously, whenever the session is cleared (LOCK) or a restore is applied. Unlocks derive
    /// their key off the UI thread, so one started before such a change must drop its result: applying it would reopen
    /// (and re-share via <see cref="Set"/>) what the user just locked. The <see cref="Changed"/> handlers are posted,
    /// so they can run too late to cancel it.</summary>
    public static int Epoch => Volatile.Read(ref _epoch);

    /// <summary>True while a master password is held (i.e. the app is unlocked).</summary>
    public static bool IsSet
    {
        get { lock (Gate) return _password.Length > 0; }
    }

    /// <summary>A pinned copy of the shared password for one unlock attempt (empty when locked). The caller owns it and
    /// must zero it (<see cref="SecureMemory.Zero(char[])"/>) when the attempt is over.</summary>
    public static char[] CopyPassword()
    {
        lock (Gate) return SecureMemory.CopyChars(_password);
    }

    /// <summary>True if <paramref name="password"/> is the shared master (constant-time over the shared length).</summary>
    public static bool Matches(ReadOnlySpan<char> password)
    {
        lock (Gate)
            return _password.Length > 0 && password.Length == _password.Length && FixedTimeEquals(password, _password);
    }

    /// <summary>Raised when the shared password is set or cleared. Handlers run synchronously;
    /// subscribers should marshal to the UI thread themselves if they touch bound state.</summary>
    public static event Action? Changed;

    /// <summary>Adopt <paramref name="password"/> as the shared master (a pinned copy is kept; the caller still zeroes
    /// its own buffer). No-op if empty or unchanged, so auto-unlock echoing the same password back doesn't loop.</summary>
    public static void Set(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty) return;
        lock (Gate)
        {
            if (password.Length == _password.Length && FixedTimeEquals(password, _password)) return;
            char[] old = _password;
            _password = SecureMemory.CopyChars(password);
            SecureMemory.Track(_password);
            SecureMemory.Release(old);
        }
        Changed?.Invoke();
    }

    /// <summary>Wipe the shared password (locks every area that follows the session).</summary>
    public static void Clear()
    {
        lock (Gate)
        {
            if (_password.Length == 0) return;
            WipeLocked();
        }
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
        lock (Gate) WipeLocked();
        RestoreApplied?.Invoke();
    }

    // Under Gate: zero the buffer in place (copies handed out are their callers' to zero) and bump the epoch.
    private static void WipeLocked()
    {
        SecureMemory.Release(_password);
        _password = Array.Empty<char>();
        Interlocked.Increment(ref _epoch);
    }

    private static bool FixedTimeEquals(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
        => System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(a),
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(b));
}
