using Renci.SshNet.Sftp;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Echoes.Helpers;

/// <summary>One entry of a remote directory listing (immutable: a refresh builds new rows).</summary>
public sealed class SshFileRow
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public bool IsDirectory { get; init; }
    public bool IsLink { get; init; }
    public long Size { get; init; }
    public DateTime Modified { get; init; }
    public string Permissions { get; init; } = string.Empty;

    /// <summary>The listed entry itself. Deleting / renaming goes through IT, not through a path: SSH.NET's path-based
    /// DeleteFile / RenameFile canonicalize the path first (SSH_FXP_REALPATH), which resolves a symlink — they would
    /// delete or rename the link's TARGET and leave the link behind. The listed ISftpFile acts on the link itself.</summary>
    internal ISftpFile? Entry { get; init; }

    public bool IsFile => !IsDirectory && !IsLink;
    public string SizeText => IsDirectory ? "—" : SshText.Bytes(Size);
    public string ModifiedText => Modified == default ? string.Empty : Modified.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
    /// <summary>The phone layout's second line.</summary>
    public string MetaText => ModifiedText.Length == 0 ? Permissions : Permissions + "  ·  " + ModifiedText;

    public static SshFileRow From(ISftpFile f) => new()
    {
        Name = f.Name,
        FullPath = f.FullName,
        IsDirectory = f.IsDirectory,
        IsLink = f.IsSymbolicLink,
        Size = f.Length,
        Modified = f.LastWriteTime,
        Permissions = SshPaths.Permissions(f.Attributes),
        Entry = f,
    };

    /// <summary>Folders first (links to folders can't be told apart without a stat each, so links sort with
    /// files), then by name, case-insensitively.</summary>
    public static int Compare(SshFileRow a, SshFileRow b)
    {
        if (a.IsDirectory != b.IsDirectory) return a.IsDirectory ? -1 : 1;
        int c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        return c != 0 ? c : string.CompareOrdinal(a.Name, b.Name);
    }
}

/// <summary>Remote (always '/'-separated) path helpers and the ls-style permission string.</summary>
public static class SshPaths
{
    public static string Combine(string dir, string name)
    {
        if (name.StartsWith('/')) return Normalize(name);
        if (dir.Length == 0) return name;
        return Normalize(dir.EndsWith('/') ? dir + name : dir + "/" + name);
    }

    /// <summary>The folder above <paramref name="path"/> ("/" stays "/").</summary>
    public static string Parent(string path)
    {
        path = Normalize(path);
        if (path == "/" || path.Length == 0) return "/";
        int i = path.LastIndexOf('/');
        if (i < 0) return ".";
        return i == 0 ? "/" : path[..i];
    }

    public static string FileName(string path)
    {
        path = path.TrimEnd('/');
        int i = path.LastIndexOf('/');
        return i < 0 ? path : path[(i + 1)..];
    }

    /// <summary>Collapses "//", "." and ".." textually (absolute paths only; a relative one is returned trimmed).</summary>
    public static string Normalize(string path)
    {
        path = path.Trim();
        if (!path.StartsWith('/')) return path.Length > 1 ? path.TrimEnd('/') : path;
        var parts = new List<string>();
        foreach (var seg in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(seg);
        }
        return "/" + string.Join('/', parts);
    }

    /// <summary>Null when <paramref name="name"/> can be a single file / folder name; else why not.</summary>
    public static string? NameProblem(string name)
    {
        if (name.Length == 0) return "Enter a name.";
        if (name is "." or "..") return "That name is reserved.";
        if (name.Contains('/')) return "A name can't contain '/'.";
        if (name.IndexOf('\0') >= 0) return "That name isn't valid.";
        if (name.Length > 255) return "That name is too long.";
        return null;
    }

    public static string Permissions(SftpFileAttributes a)
    {
        var sb = new StringBuilder(10);
        sb.Append(a.IsDirectory ? 'd' : a.IsSymbolicLink ? 'l' : a.IsBlockDevice ? 'b' : a.IsCharacterDevice ? 'c'
                  : a.IsNamedPipe ? 'p' : a.IsSocket ? 's' : '-');
        sb.Append(a.OwnerCanRead ? 'r' : '-').Append(a.OwnerCanWrite ? 'w' : '-');
        sb.Append(a.IsUIDBitSet ? (a.OwnerCanExecute ? 's' : 'S') : (a.OwnerCanExecute ? 'x' : '-'));
        sb.Append(a.GroupCanRead ? 'r' : '-').Append(a.GroupCanWrite ? 'w' : '-');
        sb.Append(a.IsGroupIDBitSet ? (a.GroupCanExecute ? 's' : 'S') : (a.GroupCanExecute ? 'x' : '-'));
        sb.Append(a.OthersCanRead ? 'r' : '-').Append(a.OthersCanWrite ? 'w' : '-');
        sb.Append(a.IsStickyBitSet ? (a.OthersCanExecute ? 't' : 'T') : (a.OthersCanExecute ? 'x' : '-'));
        return sb.ToString();
    }
}
