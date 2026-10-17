using System;
using System.Collections.Generic;
using System.Linq;

namespace Echoes.Helpers;

/// <summary>
/// Which nodes run a check: <see cref="Automatic"/> (check-host.net picks up to "max nodes"), whole regions, or nodes picked
/// one by one. Saved as text: "" (automatic), "regions:Europe|Asia", "nodes:de1.node.check-host.net,us1.node.check-host.net".
/// </summary>
public sealed class CheckHostNodeChoice
{
    public enum ChoiceMode { Automatic, Regions, Nodes }

    private CheckHostNodeChoice(ChoiceMode mode, IReadOnlyList<string> regions, IReadOnlyList<string> nodes)
    {
        Mode = mode;
        Regions = regions;
        Nodes = nodes;
    }

    public static readonly CheckHostNodeChoice Automatic = new(ChoiceMode.Automatic, Array.Empty<string>(), Array.Empty<string>());

    public ChoiceMode Mode { get; }
    public IReadOnlyList<string> Regions { get; }
    public IReadOnlyList<string> Nodes { get; }
    public bool IsAutomatic => Mode == ChoiceMode.Automatic;

    public static CheckHostNodeChoice ForRegions(IEnumerable<string> regions)
    {
        var list = regions.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim()).Distinct(StringComparer.OrdinalIgnoreCase)
                          .OrderBy(CheckHostRegions.Rank).ToList();
        return list.Count == 0 ? Automatic : new CheckHostNodeChoice(ChoiceMode.Regions, list, Array.Empty<string>());
    }

    public static CheckHostNodeChoice ForNodes(IEnumerable<string> nodeIds)
    {
        var list = nodeIds.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.OrdinalIgnoreCase)
                          .OrderBy(n => n, Comparer<string>.Create(CheckHostNode.CompareIds)).ToList();
        return list.Count == 0 ? Automatic : new CheckHostNodeChoice(ChoiceMode.Nodes, Array.Empty<string>(), list);
    }

    public string Serialize() => Mode switch
    {
        ChoiceMode.Regions => "regions:" + string.Join("|", Regions),
        ChoiceMode.Nodes => "nodes:" + string.Join(",", Nodes),
        _ => "",
    };

    public static CheckHostNodeChoice Parse(string? text)
    {
        string t = (text ?? "").Trim();
        if (t.StartsWith("regions:", StringComparison.OrdinalIgnoreCase))
            return ForRegions(t["regions:".Length..].Split('|').Where(r => CheckHostRegions.Rank(r.Trim()) < CheckHostRegions.Order.Length));
        if (t.StartsWith("nodes:", StringComparison.OrdinalIgnoreCase))
            return ForNodes(t["nodes:".Length..].Split(',').Where(IsNodeId));
        return Automatic;
    }

    /// <summary>A node id as check-host.net writes them (a host name) — a saved value is never sent unchecked.</summary>
    public static bool IsNodeId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return false;
        string s = id.Trim();
        return s.Length <= 100 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-') && s.Contains('.');
    }

    /// <summary>"Automatic", "Europe", "Europe + Asia", "3 regions", "Frankfurt, Germany", "Germany · 3 nodes", "5 nodes".</summary>
    public string Label(IReadOnlyList<CheckHostNode>? catalog)
    {
        switch (Mode)
        {
            case ChoiceMode.Regions:
                return Regions.Count <= 2 ? string.Join(" + ", Regions) : $"{Regions.Count} regions";
            case ChoiceMode.Nodes:
                if (catalog is not null)
                {
                    var known = catalog.Where(n => Nodes.Contains(n.Id, StringComparer.OrdinalIgnoreCase)).ToList();
                    if (known.Count == 1 && Nodes.Count == 1) return known[0].Location;
                    if (known.Count == Nodes.Count && known.Count > 0
                        && known.Select(n => n.CountryCode).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1)
                        return $"{known[0].Country} · {Nodes.Count} nodes";
                }
                return CheckHostFormat.Plural(Nodes.Count, "node", "nodes");
            default:
                return "Automatic";
        }
    }

    /// <summary>Every node the choice covers (before the "max nodes" cap), in catalog order. Automatic covers none.</summary>
    public List<CheckHostNode> Covered(IReadOnlyList<CheckHostNode> catalog) => Mode switch
    {
        ChoiceMode.Regions => catalog.Where(n => Regions.Contains(n.Region, StringComparer.OrdinalIgnoreCase)).ToList(),
        ChoiceMode.Nodes => catalog.Where(n => Nodes.Contains(n.Id, StringComparer.OrdinalIgnoreCase)).ToList(),
        _ => new List<CheckHostNode>(),
    };

    /// <summary>
    /// The node ids to ask for — none for <see cref="Automatic"/> (the API's max_nodes picks then). At most
    /// <paramref name="max"/>, spread over as many countries as possible: one node per country in turn. Without a catalog
    /// (it couldn't be loaded) picked nodes are sent as saved; regions need it, so that is null then.
    /// </summary>
    public IReadOnlyList<string>? Resolve(IReadOnlyList<CheckHostNode>? catalog, int max)
    {
        max = Math.Clamp(max, 1, 100);
        if (Mode == ChoiceMode.Automatic) return Array.Empty<string>();
        if (catalog is null) return Mode == ChoiceMode.Nodes ? Nodes.Take(max).ToList() : null;
        return Spread(Covered(catalog), max).Select(n => n.Id).ToList();
    }

    /// <summary>Up to <paramref name="max"/> nodes, round-robin over the countries (alphabetical), each country's nodes in id order.</summary>
    public static List<CheckHostNode> Spread(IEnumerable<CheckHostNode> nodes, int max)
    {
        var byCountry = nodes.GroupBy(n => n.CountryCode.Length > 0 ? n.CountryCode : n.Country, StringComparer.OrdinalIgnoreCase)
                             .OrderBy(g => g.First().Country, StringComparer.OrdinalIgnoreCase)
                             .Select(g => new Queue<CheckHostNode>(g.OrderBy(n => n.Id, Comparer<string>.Create(CheckHostNode.CompareIds))))
                             .ToList();
        var picked = new List<CheckHostNode>();
        while (picked.Count < max && byCountry.Count > 0)
        {
            for (int i = 0; i < byCountry.Count && picked.Count < max; i++)
                picked.Add(byCountry[i].Dequeue());
            byCountry.RemoveAll(q => q.Count == 0);
        }
        return picked;
    }
}
