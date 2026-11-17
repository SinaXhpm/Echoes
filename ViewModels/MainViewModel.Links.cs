using System;

namespace Echoes.ViewModels;

/// <summary>
/// What a tool can ask of the rest of the app: show another tool, or hand it a value to work on. MainViewModel serves
/// it (it holds the tools' view-models, each made on first use, and both shells follow its <see cref="MainViewModel.ToolRequested"/>);
/// a tool that uses it gets it when it is made. The DNS results hand their addresses on with it; any tool can, the same way.
/// </summary>
public interface IToolLinks
{
    /// <summary>Shows the tool with this nav tag ("DNS", "IP INFO" …) as if it were picked in the menu.</summary>
    void OpenTool(string tag);

    /// <summary>IP Info, looking up <paramref name="ip"/>.</summary>
    void LookUpIp(string ip);

    /// <summary>DNS &amp; WHOIS, running WHOIS (RDAP) for <paramref name="query"/>: a domain, an IP or an AS number.</summary>
    void Whois(string query);
}

/// <summary>A tool to show (its nav tag). <paramref name="Apply"/>: what to hand it once its page is there, given the
/// view-model of the tab (or phone page) that shows it. <paramref name="Background"/>: the tool started on its own (the
/// Monitor at launch); the desktop gives it a tab if it has none, without switching to it.</summary>
public sealed record ToolRequest(string Tag, Action<object>? Apply = null, bool Background = false);

public partial class MainViewModel : IToolLinks
{
    /// <summary>A tool asked for another tool's page. Both shells select it (the desktop: the tool's most recently used
    /// tab, or a new one), which builds the page on a first visit the way a click does, then run the request's Apply.</summary>
    public event Action<ToolRequest>? ToolRequested;

    public void OpenTool(string tag) => ToolRequested?.Invoke(new ToolRequest(tag));

    /// <summary>A tool started by itself (the Monitor at launch): its tab is there whenever it runs.</summary>
    public void ShowToolStarted(string tag) => ToolRequested?.Invoke(new ToolRequest(tag, null, Background: true));

    public void LookUpIp(string ip) => Hand("IP INFO", tool => (tool as IpInfoViewModel)?.LookUp(ip));

    public void Whois(string query) => Hand("DNS", tool => (tool as DnsViewModel)?.Whois(query));

    // The page first: the shell shows it (making its view-model) and hands that view-model over. With no shell listening
    // (a test harness), the main view-model gets it.
    private void Hand(string tag, Action<object> apply)
    {
        if (ToolRequested is { } requested) requested(new ToolRequest(tag, apply));
        else if (MainTool(tag) is { } tool) apply(tool);
    }
}
