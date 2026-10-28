using System;
using System.Collections.Generic;
using System.Linq;

namespace Echoes.Helpers;

/// <summary>
/// check-host.net's node list as it was on 28 October 2026 (48 nodes), for when the live list (/nodes/hosts) can't be
/// loaded: the node picker still shows regions and nodes, and a run that moves to Globalping still knows where each picked
/// node is. A run on check-host.net itself uses the live list whenever it loads.
/// </summary>
public static class CheckHostSnapshot
{
    // short id | country code | country | city | ASN
    private const string Table =
        "at1|at|Austria|Vienna|AS64457\n" +
        "bg1|bg|Bulgaria|Sofia|AS9028\n" +
        "br1|br|Brazil|Sao Paulo|AS268581\n" +
        "ca1|ca|Canada|Vancouver|AS396993\n" +
        "ch1|ch|Switzerland|Zurich|AS51852\n" +
        "ch2|ch|Switzerland|Zurich|AS13030\n" +
        "de2|de|Germany|Langen|AS212000\n" +
        "de4|de|Germany|Frankfurt|AS34549\n" +
        "es1|es|Spain|Madrid|AS215691\n" +
        "es2|es|Spain|Barcelona|AS26141\n" +
        "fr2|fr|France|Paris|AS12876\n" +
        "hk1|hk|Hong Kong|Hong Kong|AS207713\n" +
        "hu1|hu|Hungary|Nyiregyhaza|AS211619\n" +
        "id1|id|Indonesia|Jakarta|AS200177\n" +
        "il1|il|Israel|Tel Aviv|AS206446\n" +
        "il2|il|Israel|Netanya|AS206446\n" +
        "in1|in|India|Mumbai|AS218984\n" +
        "ir1|ir|Iran|Tehran|AS47430\n" +
        "ir2|ir|Iran|Isfahan|AS209279\n" +
        "ir3|ir|Iran|Shiraz|AS213953\n" +
        "ir4|ir|Iran|Shiraz|AS212077\n" +
        "ir5|ir|Iran|Tehran|AS214431\n" +
        "ir7|ir|Iran|Tehran|AS213727\n" +
        "it2|it|Italy|Milan|AS60798\n" +
        "jp1|jp|Japan|Tokyo|AS149042\n" +
        "kz1|kz|Kazakhstan|Karaganda|AS203087\n" +
        "md1|md|Moldova|Chisinau|AS43289\n" +
        "nl1|nl|Netherlands|Amsterdam|AS14576\n" +
        "nl2|nl|Netherlands|Meppel|AS206446\n" +
        "pl2|pl|Poland|Warsaw|AS214379\n" +
        "pt1|pt|Portugal|Viana|AS44222\n" +
        "rs1|rs|Serbia|Belgrade|AS35779\n" +
        "ru1|ru|Russia|Moscow|AS14576\n" +
        "ru2|ru|Russia|Moscow|AS210644\n" +
        "ru3|ru|Russia|Saint Petersburg|AS210644\n" +
        "se1|se|Sweden|Stockholm|AS200019\n" +
        "se2|se|Sweden|Stockholm|AS214379\n" +
        "sg1|sg|Singapore|Singapore|AS141995\n" +
        "si1|si|Slovenia|Maribor|AS49592\n" +
        "tr1|tr|Turkey|Istanbul|AS211557\n" +
        "tr2|tr|Turkey|Istanbul|AS44620\n" +
        "ua1|ua|Ukraine|Khmelnytskyi|AS201094\n" +
        "ua3|ua|Ukraine|Kyiv|AS13335\n" +
        "uk1|gb|UK|London|AS213535\n" +
        "us1|us|USA|Los Angeles|AS18978\n" +
        "us3|us|USA|Atlanta|AS215540\n" +
        "us5|us|USA|New York|AS213535\n" +
        "vn1|vn|Vietnam|Ho Chi Minh City|AS63760";

    private static IReadOnlyList<CheckHostNode>? s_nodes;

    public static IReadOnlyList<CheckHostNode> Nodes => s_nodes ??= Table.Split('\n').Select(line =>
    {
        var f = line.Split('|');
        return new CheckHostNode(f[0] + ".node.check-host.net", f[1], f[2], f[3], "", f[4]);
    }).ToList();

    /// <summary>A node by id: from <paramref name="catalog"/>, else this list, else only the country its id names
    /// ("de7.node.check-host.net" is in Germany, "uk2" in the UK); null when even that can't be told.</summary>
    public static CheckHostNode? Find(string id, IReadOnlyList<CheckHostNode>? catalog)
    {
        var known = catalog?.FirstOrDefault(n => string.Equals(n.Id, id, StringComparison.OrdinalIgnoreCase))
                    ?? Nodes.FirstOrDefault(n => string.Equals(n.Id, id, StringComparison.OrdinalIgnoreCase));
        if (known is not null) return known;
        string s = CheckHostNode.Short(id);
        if (s.Length < 3 || !char.IsAsciiLetter(s[0]) || !char.IsAsciiLetter(s[1]) || !s[2..].All(char.IsAsciiDigit)) return null;
        string cc = s[..2].ToLowerInvariant() == "uk" ? "gb" : s[..2].ToLowerInvariant();
        // only a real country: Globalping refuses a whole request over one code it doesn't know
        if (!CloudflareCountries.IsCode(cc) || cc is "xx" or "t1") return null;
        return new CheckHostNode(id, cc, CloudflareCountries.Name(cc), "", "", "");
    }
}
