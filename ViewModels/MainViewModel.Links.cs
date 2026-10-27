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

public partial class MainViewModel : IToolLinks
{
    /// <summary>A tool asked for another tool's page (its nav tag). Both shells select that entry, which builds the page
    /// on a first visit the way a click does.</summary>
    public event Action<string>? ToolRequested;

    public void OpenTool(string tag) => ToolRequested?.Invoke(tag);

    // The page first: selecting it makes the view and, through the lazy getter, the view-model it is then handed to.
    public void LookUpIp(string ip)
    {
        OpenTool("IP INFO");
        IpInfoVM.LookUp(ip);
    }

    public void Whois(string query)
    {
        OpenTool("DNS");
        DnsVM.Whois(query);
    }
}
