using System.Collections.Concurrent;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>
/// Classic WHOIS chains (Whois43) followed through stand-in servers (its test hook, no network), and what the monitor's
/// expiry check reads from them. Every test that sets the hook is in this class: xUnit runs one class's tests one after
/// the other.
/// </summary>
public sealed class WhoisTests : IDisposable
{
    private const string Verisign = "whois.verisign-grs.com";
    private const string Registrar = "whois.registrar.example";

    private const string IanaCom = "% IANA WHOIS server\r\n\r\nrefer:        whois.verisign-grs.com\r\n\r\ndomain:       COM\r\n";
    private const string IanaNoRefer = "% IANA WHOIS server\r\n\r\ndomain:       UK\r\n\r\norganisation: Nominet UK\r\n";
    private const string RegistryCom =
        "   Domain Name: EXAMPLE.COM\r\n   Registrar WHOIS Server: whois.registrar.example\r\n"
        + "   Updated Date: 2026-08-14T07:01:34Z\r\n   Registry Expiry Date: 2027-08-13T04:00:00Z\r\n";
    private const string RateLimited = "Your connection limit exceeded. Please slow down and try again later.\r\n";

    private readonly ConcurrentQueue<(string Server, string Query)> _asked = new();

    public void Dispose() => Whois43.AskHook = null;

    // Stand-in servers: each answers from the map, one that isn't there answers nothing until the hop is cancelled.
    private void Serve(Dictionary<string, string> answers)
        => Whois43.AskHook = async (server, query, ct) =>
        {
            _asked.Enqueue((server, query));
            if (answers.TryGetValue(server, out var answer)) return answer;
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("not reached");
        };

    private static CancellationToken Test => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_whois_nic_server_named_from_an_uppercase_query_is_asked_in_lowercase()
    {
        Serve(new() { [Whois43.Iana] = IanaNoRefer, ["whois.nic.uk"] = "Domain name:\r\n    example.uk\r\n\r\nExpiry date:  02-Aug-2027\r\n" });
        var answer = await Whois43.LookUpAsync("example.UK", Whois43.Kind.Domain, Test);
        Assert.Equal(new[] { Whois43.Iana, "whois.nic.uk" }, answer.Servers);
        Assert.Null(answer.Note);
        Assert.Contains("example.uk", answer.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_referral_written_with_a_trailing_dot_is_followed()
    {
        Serve(new() { [Whois43.Iana] = "refer: whois.registry.example.\r\n", ["whois.registry.example"] = "domain: example.example\r\n" });
        var answer = await Whois43.LookUpAsync("example.example", Whois43.Kind.Domain, Test);
        Assert.Equal(new[] { Whois43.Iana, "whois.registry.example" }, answer.Servers);
        Assert.Null(answer.Note);
    }

    [Fact]
    public async Task A_next_server_that_is_no_host_name_leaves_a_note_so_IANAs_record_is_not_taken_for_the_answer()
    {
        Serve(new() { [Whois43.Iana] = "% This query returned 0 objects.\r\n" });
        var answer = await Whois43.LookUpAsync("пример.рф", Whois43.Kind.Domain, Test);
        Assert.Equal(new[] { Whois43.Iana }, answer.Servers);
        Assert.NotNull(answer.Note);
        Assert.Contains("wasn't asked", answer.Note, StringComparison.Ordinal);
        Assert.Single(_asked);   // nothing was asked but IANA
    }

    [Fact]
    public async Task IANAs_own_record_with_no_server_to_ask_after_it_is_the_answer()
    {
        // a reserved block: IANA holds it, nothing to follow, no note
        Serve(new() { [Whois43.Iana] = "inetnum: 240.0.0.0 - 255.255.255.255\r\norganisation: IANA - Reserved\r\n" });
        var answer = await Whois43.LookUpAsync("240.0.0.1", Whois43.Kind.Ip, Test);
        Assert.Equal(new[] { Whois43.Iana }, answer.Servers);
        Assert.Null(answer.Note);
    }

    [Fact]
    public async Task A_server_still_silent_when_the_chains_deadline_runs_out_leaves_the_answers_before_it()
    {
        // the registrar never answers: its hop is cut by the chain's own deadline (WhoisLookup gives the chain one a
        // second inside its source's share), and the registry's answer stays, with a note
        Serve(new() { [Whois43.Iana] = IanaCom, [Verisign] = RegistryCom });
        var answer = await Whois43.LookUpAsync("example.com", Whois43.Kind.Domain, Test, TimeSpan.FromMilliseconds(600));
        Assert.Equal(new[] { Whois43.Iana, Verisign }, answer.Servers);
        Assert.Equal($"{Registrar} didn't answer (timed out)", answer.Note);
        Assert.Contains("Registry Expiry Date", answer.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_callers_own_cancellation_still_ends_the_chain()
    {
        Serve(new() { [Whois43.Iana] = IanaCom, [Verisign] = RegistryCom });
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Test);
        stop.CancelAfter(TimeSpan.FromMilliseconds(400));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Whois43.LookUpAsync("example.com", Whois43.Kind.Domain, stop.Token));
    }

    [Fact]
    public async Task Each_servers_answer_is_kept_and_the_registrys_expiry_wins_over_the_registrars_reply()
    {
        Serve(new() { [Whois43.Iana] = IanaCom, [Verisign] = RegistryCom, [Registrar] = RateLimited });
        var answer = await Whois43.LookUpAsync("example.com", Whois43.Kind.Domain, Test);
        Assert.Equal(new[] { Whois43.Iana, Verisign, Registrar }, answer.Servers);
        Assert.Equal(3, answer.Replies.Count);
        Assert.Null(MonitorChecks.WhoisExpiry(answer.Text));   // the deepest answer alone has no expiry
        Assert.Equal(new MonitorRdapResult(MonitorRdapOutcome.Found, new DateTime(2027, 8, 13, 4, 0, 0, DateTimeKind.Utc)),
                     MonitorChecks.WhoisVerdict(answer));
    }

    private static Whois43.Answer Chain(string[] servers, params string[] replies)
        => new(replies[^1], servers, null) { Replies = replies };

    [Fact]
    public void The_registrys_expiry_comes_before_a_different_one_from_the_registrar()
    {
        var answer = Chain(new[] { Whois43.Iana, Verisign, Registrar }, IanaCom, RegistryCom,
                           "Registrar Registration Expiration Date: 2028-01-01T00:00:00Z\r\n");
        Assert.Equal(new DateTime(2027, 8, 13, 4, 0, 0, DateTimeKind.Utc), MonitorChecks.WhoisVerdict(answer)?.ExpiresUtc);
    }

    [Fact]
    public void The_registrars_expiry_counts_when_the_registry_states_none()
    {
        var answer = Chain(new[] { Verisign, Registrar }, "Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: whois.registrar.example\r\n",
                           "Registrar Registration Expiration Date: 2028-01-01T00:00:00Z\r\n");
        Assert.Equal(new MonitorRdapResult(MonitorRdapOutcome.Found, new DateTime(2028, 1, 1, 0, 0, 0, DateTimeKind.Utc)),
                     MonitorChecks.WhoisVerdict(answer));
    }

    [Fact]
    public void Not_registered_is_the_registrys_to_say()
    {
        var answer = Chain(new[] { Whois43.Iana, Verisign }, IanaCom, "No match for domain \"NOPE-EXAMPLE.COM\".\r\n");
        Assert.Equal(new MonitorRdapResult(MonitorRdapOutcome.NoData, null), MonitorChecks.WhoisVerdict(answer));
    }

    [Fact]
    public void An_answer_with_neither_an_expiry_nor_not_registered_is_no_verdict()
    {
        // a rate limit (or a format not read): no verdict, so the monitor keeps what it knew instead of "no expiry listed"
        Assert.Null(MonitorChecks.WhoisVerdict(Chain(new[] { Whois43.Iana, "whois.nic.example" }, IanaCom, RateLimited)));
        // IANA's record alone names the registry only
        Assert.Null(MonitorChecks.WhoisVerdict(Chain(new[] { Whois43.Iana }, IanaCom)));
    }
}
