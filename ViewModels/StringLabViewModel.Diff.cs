using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _diffLeft = string.Empty;
    [ObservableProperty] private string _diffRight = string.Empty;
    [ObservableProperty] private string _diffOutput = string.Empty;
    [ObservableProperty] private bool _diffIgnoreCase;
    [ObservableProperty] private bool _diffIgnoreWhitespace;
    [ObservableProperty] private bool _diffIgnoreBlankLines;

    // Unchanged lines kept around each change, as in `diff -u`.
    private const int DiffContext = 3;

    // One run of the edit script: '=' (same on both sides), '-' (left only) or '+' (right only),
    // covering left lines [I1, I2) and right lines [J1, J2).
    private readonly record struct DiffOp(char Tag, int I1, int I2, int J1, int J2);

    [RelayCommand]
    private Task RunDiff()
    {
        string left = DiffLeft, right = DiffRight;
        bool ignoreCase = DiffIgnoreCase, ignoreWs = DiffIgnoreWhitespace, ignoreBlank = DiffIgnoreBlankLines;
        return RunOffUi("diff", () => Diff(left, right, ignoreCase, ignoreWs, ignoreBlank), r => DiffOutput = r, "Diff: ");
    }

    private static string Diff(string left, string right, bool ignoreCase, bool ignoreWs, bool ignoreBlank)
    {
        var (a, aNo) = SplitDiffLines(left, ignoreBlank);
        var (b, bNo) = SplitDiffLines(right, ignoreBlank);

        // Compare interned ids of normalised keys, but print the original lines.
        var ids = new Dictionary<string, int>(StringComparer.Ordinal);
        int[] ka = KeyIds(a, ids, ignoreCase, ignoreWs);
        int[] kb = KeyIds(b, ids, ignoreCase, ignoreWs);

        // Identical head/tail need no LCS table — real edits are usually small islands in big files.
        int n = a.Count, m = b.Count;
        int pre = 0;
        while (pre < n && pre < m && ka[pre] == kb[pre]) pre++;
        int suf = 0;
        while (suf < n - pre && suf < m - pre && ka[n - 1 - suf] == kb[m - 1 - suf]) suf++;
        int mn = n - pre - suf, mm = m - pre - suf;

        // Guard the O(n*m) matrix on what's left: ~8M cells ≈ 32 MB of ints is plenty for real diffs.
        const long maxCells = 8_000_000;
        if ((long)mn * mm > maxCells)
            throw new InvalidOperationException($"Changed region too large to diff ({mn:N0}×{mm:N0} lines). Compare smaller sections.");

        var lcs = new int[mn + 1, mm + 1];
        for (int i = mn - 1; i >= 0; i--)
            for (int j = mm - 1; j >= 0; j--)
                lcs[i, j] = ka[pre + i] == kb[pre + j] ? lcs[i + 1, j + 1] + 1 : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);

        // Walk the table into an edit script of runs (removals before additions on a tie).
        var ops = new List<DiffOp>();
        void Add(char tag, int i1, int i2, int j1, int j2)
        {
            if (ops.Count > 0 && ops[^1].Tag == tag) ops[^1] = ops[^1] with { I2 = i2, J2 = j2 };
            else ops.Add(new DiffOp(tag, i1, i2, j1, j2));
        }
        if (pre > 0) Add('=', 0, pre, 0, pre);
        int x = 0, y = 0;
        while (x < mn && y < mm)
        {
            int i = pre + x, j = pre + y;
            if (ka[i] == kb[j]) { Add('=', i, i + 1, j, j + 1); x++; y++; }
            else if (lcs[x + 1, y] >= lcs[x, y + 1]) { Add('-', i, i + 1, j, j); x++; }
            else { Add('+', i, i, j, j + 1); y++; }
        }
        if (x < mn) Add('-', pre + x, pre + mn, pre + y, pre + y);
        if (y < mm) Add('+', pre + x, pre + x, pre + y, pre + mm);
        if (suf > 0) Add('=', n - suf, n, m - suf, m);

        int added = 0, removed = 0;
        foreach (var op in ops)
        {
            if (op.Tag == '-') removed += op.I2 - op.I1;
            else if (op.Tag == '+') added += op.J2 - op.J1;
        }

        // Only the changes and their context, not every unchanged line of two big files.
        var sb = new StringBuilder();
        foreach (var hunk in DiffHunks(ops))
        {
            sb.Append("@@ -").Append(HunkRange(hunk[0].I1, hunk[^1].I2, aNo))
              .Append(" +").Append(HunkRange(hunk[0].J1, hunk[^1].J2, bNo)).AppendLine(" @@");
            foreach (var op in hunk)
            {
                if (op.Tag == '+')
                    for (int j = op.J1; j < op.J2; j++) sb.Append("+ ").AppendLine(b[j]);
                else
                    for (int i = op.I1; i < op.I2; i++) sb.Append(op.Tag == '-' ? "- " : "  ").AppendLine(a[i]);
            }
        }

        var ignored = new List<string>();
        if (ignoreCase) ignored.Add("case");
        if (ignoreWs) ignored.Add("whitespace");
        if (ignoreBlank) ignored.Add("blank lines");
        string summary = (added == 0 && removed == 0 ? "# Identical" : $"# +{added} added, -{removed} removed")
                         + (ignored.Count > 0 ? "   (ignoring " + string.Join(", ", ignored) + ")" : "");

        return sb.Length == 0 ? summary : summary + Environment.NewLine + Environment.NewLine + sb.ToString().TrimEnd('\r', '\n');
    }

    // Python difflib's grouped opcodes (what `diff -u` prints): each change keeps DiffContext unchanged
    // lines on either side, and changes closer than twice that share one hunk.
    private static List<List<DiffOp>> DiffHunks(List<DiffOp> ops)
    {
        var hunks = new List<List<DiffOp>>();
        var group = new List<DiffOp>();
        for (int k = 0; k < ops.Count; k++)
        {
            var op = ops[k];
            if (op.Tag == '=')
            {
                // only the context next to a change: the tail of a leading run, the head of a trailing one
                if (k == 0) op = op with { I1 = Math.Max(op.I1, op.I2 - DiffContext), J1 = Math.Max(op.J1, op.J2 - DiffContext) };
                if (k == ops.Count - 1) op = op with { I2 = Math.Min(op.I2, op.I1 + DiffContext), J2 = Math.Min(op.J2, op.J1 + DiffContext) };
                if (op.I2 - op.I1 > 2 * DiffContext)
                {
                    // a long unchanged stretch ends this hunk and starts the next
                    group.Add(op with { I2 = op.I1 + DiffContext, J2 = op.J1 + DiffContext });
                    hunks.Add(group);
                    group = new List<DiffOp>();
                    op = op with { I1 = op.I2 - DiffContext, J1 = op.J2 - DiffContext };
                }
            }
            group.Add(op);
        }
        if (group.Count > 0 && !(group.Count == 1 && group[0].Tag == '=')) hunks.Add(group);
        return hunks;
    }

    // "start,count" of a hunk side in the user's own 1-based line numbers (lines hidden by "Ignore
    // blank lines" still count), as `diff -u` writes it: a single line is just "start", and an empty
    // range names the line before it.
    private static string HunkRange(int start, int stop, int[] lineNo)
    {
        if (stop <= start) return (start > 0 ? lineNo[start - 1] : 0) + ",0";
        int first = lineNo[start], count = lineNo[stop - 1] - first + 1;
        return count == 1 ? first.ToString() : first + "," + count;
    }

    // Lines, plus each one's number in the original text (for the hunk headers).
    private static (List<string> Lines, int[] LineNo) SplitDiffLines(string s, bool ignoreBlank)
    {
        string[] all = s.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var lines = new List<string>(all.Length);
        var no = new List<int>(all.Length);
        for (int i = 0; i < all.Length; i++)
        {
            if (ignoreBlank && string.IsNullOrWhiteSpace(all[i])) continue;
            lines.Add(all[i]);
            no.Add(i + 1);
        }
        return (lines, no.ToArray());
    }

    private static int[] KeyIds(List<string> lines, Dictionary<string, int> ids, bool ignoreCase, bool ignoreWs)
    {
        var result = new int[lines.Count];
        var sb = new StringBuilder();
        for (int i = 0; i < lines.Count; i++)
        {
            string key = lines[i];
            if (ignoreWs)
            {
                // like `diff -w`: whitespace anywhere in the line doesn't count
                sb.Clear();
                foreach (char c in key) if (!char.IsWhiteSpace(c)) sb.Append(c);
                key = sb.ToString();
            }
            if (ignoreCase) key = key.ToUpperInvariant();
            if (!ids.TryGetValue(key, out int id)) { id = ids.Count; ids[key] = id; }
            result[i] = id;
        }
        return result;
    }
}
