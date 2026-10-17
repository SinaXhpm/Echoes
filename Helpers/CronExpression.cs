using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Echoes.Helpers;

/// <summary>
/// A pure-managed parser / evaluator / describer for standard 5-field Unix cron expressions
/// (minute hour day-of-month month day-of-week). No shell-out, no external library — safe for AOT,
/// trimming and Android. Supports <c>*</c>, <c>*/n</c>, <c>a</c>, <c>a-b</c>, <c>a-b/n</c>, comma
/// lists, and month/day names. Day-of-week accepts 0-7 (0 and 7 = Sunday). Implements the classic
/// Vixie day-of-month / day-of-week OR rule.
/// </summary>
public sealed class CronExpression
{
    private static readonly string[] MonthNames =
        { "", "January", "February", "March", "April", "May", "June",
             "July", "August", "September", "October", "November", "December" };
    private static readonly string[] DayNames =
        { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
    private static readonly Dictionary<string, int> MonthAbbr = new(StringComparer.OrdinalIgnoreCase)
    { {"JAN",1},{"FEB",2},{"MAR",3},{"APR",4},{"MAY",5},{"JUN",6},{"JUL",7},{"AUG",8},{"SEP",9},{"OCT",10},{"NOV",11},{"DEC",12} };
    private static readonly Dictionary<string, int> DowAbbr = new(StringComparer.OrdinalIgnoreCase)
    { {"SUN",0},{"MON",1},{"TUE",2},{"WED",3},{"THU",4},{"FRI",5},{"SAT",6} };

    public string[] Fields { get; }
    public string? Error { get; private set; }
    public bool IsValid => Error is null;

    private readonly bool[] _min = new bool[60];
    private readonly bool[] _hour = new bool[24];
    private readonly bool[] _dom = new bool[32];   // 1-31
    private readonly bool[] _month = new bool[13];  // 1-12
    private readonly bool[] _dow = new bool[7];     // 0-6
    private bool _domRestricted, _dowRestricted;

    private CronExpression(string[] fields) { Fields = fields; }

    /// <summary>Parse a 5-field expression. Never throws — check <see cref="IsValid"/> / <see cref="Error"/>.</summary>
    public static CronExpression Parse(string expression)
    {
        var parts = (expression ?? string.Empty).Trim()
            .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        var cron = new CronExpression(parts);
        if (parts.Length != 5) { cron.Error = $"Expected 5 fields, got {parts.Length}."; return cron; }
        try
        {
            Fill(cron._min, parts[0], 0, 59, null);
            Fill(cron._hour, parts[1], 0, 23, null);
            Fill(cron._dom, parts[2], 1, 31, null);
            Fill(cron._month, parts[3], 1, 12, MonthAbbr);
            FillDow(cron._dow, parts[4]);
            // Vixie / cronie decide "restricted" by the field's FIRST character: "*/2" counts as
            // unrestricted just like "*", so "0 0 */2 * 1" means odd days that are Mondays (AND),
            // not odd days OR Mondays. Only fields that don't start with '*' get the OR rule.
            cron._domRestricted = !parts[2].StartsWith('*');
            cron._dowRestricted = !parts[4].StartsWith('*');
        }
        catch (Exception ex) { cron.Error = ex.Message; }
        return cron;
    }

    private static void Fill(bool[] set, string field, int min, int max, Dictionary<string, int>? names)
    {
        field = field.Trim();
        if (field.Length == 0) throw new FormatException("Empty field.");
        foreach (var tok in field.Split(','))
        {
            var t = tok.Trim();
            if (t.Length == 0) throw new FormatException("Empty list item.");

            int step = 1;
            string rangePart = t;
            int slash = t.IndexOf('/');
            if (slash >= 0)
            {
                rangePart = t[..slash];
                if (!int.TryParse(t[(slash + 1)..], out step) || step < 1)
                    throw new FormatException($"Bad step in '{t}'.");
            }

            int lo, hi;
            if (rangePart == "*")
            {
                lo = min; hi = max;
            }
            else
            {
                int dash = rangePart.IndexOf('-');
                if (dash > 0)
                {
                    lo = Val(rangePart[..dash], names, min, max);
                    hi = Val(rangePart[(dash + 1)..], names, min, max);
                }
                else
                {
                    lo = Val(rangePart, names, min, max);
                    hi = slash >= 0 ? max : lo;   // "a/n" means a..max step n
                }
            }
            if (lo < min || hi > max || lo > hi)
                throw new FormatException($"'{t}' out of range {min}-{max}.");
            // long: an int v + a huge step ("59/2147483647") overflowed negative and surfaced as "Index was outside the
            // bounds of the array" instead of simply ending the loop.
            for (long v = lo; v <= hi; v += step) set[v] = true;
        }
    }

    // Day-of-week is special: accept 0-7 where both 0 and 7 mean Sunday.
    private static void FillDow(bool[] set, string field)
    {
        var tmp = new bool[8];
        Fill(tmp, field, 0, 7, DowAbbr);
        for (int i = 0; i <= 7; i++) if (tmp[i]) set[i % 7] = true;
    }

    private static int Val(string s, Dictionary<string, int>? names, int min, int max)
    {
        s = s.Trim();
        if (names != null && names.TryGetValue(s, out int n)) return n;
        if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v)) return v;
        throw new FormatException($"'{s}' is not a valid value.");
    }

    public bool Matches(DateTime dt) => _min[dt.Minute] && _hour[dt.Hour] && _month[dt.Month] && DayMatches(dt);

    private bool DayMatches(DateTime dt)
    {
        bool domOk = _dom[dt.Day];
        bool dowOk = _dow[(int)dt.DayOfWeek];
        // Vixie rule: when BOTH day fields are restricted, a match on EITHER counts.
        if (_domRestricted && _dowRestricted) return domOk || dowOk;
        return domOk && dowOk;
    }

    /// <summary>Upcoming run times strictly after <paramref name="from"/>. Bounded so an impossible
    /// expression (e.g. Feb 30) can't loop forever.</summary>
    public List<DateTime> NextRuns(DateTime from, int count)
    {
        var runs = new List<DateTime>();
        if (!IsValid) return runs;
        var t = new DateTime(from.Year, from.Month, from.Day, from.Hour, from.Minute, 0, from.Kind).AddMinutes(1);
        var limit = t.AddYears(6);   // safety horizon
        while (t < limit && runs.Count < count)
        {
            // When the month, day or hour can't match, no minute inside it can either: jump to the start
            // of the next one. Same runs as testing every minute, which walked ~3 M minutes per keystroke
            // for a yearly or impossible expression (≈50 ms desktop, 200 ms on a phone).
            if (!_month[t.Month]) t = new DateTime(t.Year, t.Month, 1, 0, 0, 0, t.Kind).AddMonths(1);
            else if (!DayMatches(t)) t = t.Date.AddDays(1);
            else if (!_hour[t.Hour]) t = new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0, t.Kind).AddHours(1);
            else
            {
                if (_min[t.Minute]) runs.Add(t);
                t = t.AddMinutes(1);
            }
        }
        return runs;
    }

    // ---------- human-readable description ----------

    public string Describe()
    {
        if (!IsValid) return "Invalid expression.";
        string time = DescribeTime(Fields[0], Fields[1]);
        var clauses = new List<string> { time };

        string dow = DescribeDow(Fields[4]);
        string dom = DescribeDom(Fields[2]);
        // Both day fields restricted → the OR rule: "30 4 1,15 * 5" runs on the 1st, the 15th AND every
        // Friday. Listed as "on Friday, on day-of-month 1,15" it read as "Fridays that are the 1st/15th".
        if (_domRestricted && _dowRestricted) clauses.Add($"{dom} or {dow}");
        else
        {
            if (dow.Length > 0) clauses.Add(dow);
            if (dom.Length > 0) clauses.Add(dom);
        }

        string month = DescribeMonth(Fields[3]);
        if (month.Length > 0) clauses.Add(month);

        string s = string.Join(", ", clauses);
        return char.ToUpperInvariant(s[0]) + s[1..] + ".";
    }

    private static string DescribeTime(string min, string hour)
    {
        min = min.Trim(); hour = hour.Trim();
        bool minEvery = min == "*", hourEvery = hour == "*";
        bool minSingle = int.TryParse(min, out int m);
        bool hourSingle = int.TryParse(hour, out int h);

        if (minEvery && hourEvery) return "every minute";
        if (IsStep(min, out int ms) && hourEvery) return $"every {ms} minutes";
        if (minSingle && hourEvery) return m == 0 ? "at the start of every hour" : $"at minute {m} of every hour";
        if (minEvery && hourSingle) return $"every minute of {Hour12(h)}";
        if (minSingle && hourSingle) return $"at {h:00}:{m:00}";
        if (minSingle && IsStep(hour, out int hs)) return $"at minute {m} past every {hs} hours";
        return $"at minute(s) {min} of hour(s) {hour}";
    }

    private static bool IsStep(string field, out int n)
    {
        n = 0;
        if (field.StartsWith("*/", StringComparison.Ordinal) && int.TryParse(field[2..], out n)) return true;
        return false;
    }

    private static string Hour12(int h)
    {
        string ap = h < 12 ? "AM" : "PM";
        int hh = h % 12; if (hh == 0) hh = 12;
        return $"{hh} {ap}";
    }

    private static string DescribeDow(string field)
    {
        field = field.Trim();
        if (field == "*") return "";
        // weekday / weekend shorthands
        if (field is "1-5") return "Monday through Friday";
        if (field is "0,6" or "6,0" or "0,7" or "sat,sun" or "sun,sat") return "on weekends";
        var names = MapList(field, DowAbbr, v => DayNames[v % 7]);
        return names is null ? $"on day-of-week {field}" : "on " + names;
    }

    private static string DescribeMonth(string field)
    {
        field = field.Trim();
        if (field == "*") return "";
        var names = MapList(field, MonthAbbr, v => MonthNames[v]);
        return names is null ? $"in month {field}" : "in " + names;
    }

    private static string DescribeDom(string field)
    {
        field = field.Trim();
        if (field == "*") return "";
        if (IsStep(field, out int n)) return $"every {n} days of the month";
        return $"on day-of-month {field}";
    }

    // Turn "1-5" / "1,3,5" / "JAN,MAR" into "Monday through Friday" / "A, B and C". Returns null for
    // anything with steps or shapes we don't prettify (caller falls back to the raw field).
    private static string? MapList(string field, Dictionary<string, int> abbr, Func<int, string> name)
    {
        try
        {
            var items = new List<string>();
            foreach (var tok in field.Split(','))
            {
                var t = tok.Trim();
                if (t.Contains('/')) return null;
                int dash = t.IndexOf('-');
                if (dash > 0)
                {
                    int a = Val(t[..dash], abbr, 0, 12), b = Val(t[(dash + 1)..], abbr, 0, 12);
                    items.Add($"{name(a)} through {name(b)}");
                }
                else items.Add(name(Val(t, abbr, 0, 12)));
            }
            if (items.Count == 1) return items[0];
            return string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1];
        }
        catch { return null; }
    }
}
