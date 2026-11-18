using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Echoes.Helpers;
using Echoes.Tests.Support;
using Echoes.ViewModels;

namespace Echoes.Tests;

/// <summary>The tests that point the Hetzner client, the Cloudflare client or the public-IP lookup at a stand-in server:
/// those roots are process-wide, so these tests run one after another.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class HetznerCollection
{
    public const string Name = "Hetzner API";
}

/// <summary>
/// The Hetzner Cloud client against a stand-in API on this computer's loopback address: refusals (401, a read-only
/// token's 403), pagination, the rate limit, action polling, the checks on names and ids that go into a URL, and that
/// the token never shows in an error.
/// </summary>
[Collection(HetznerCollection.Name)]
public sealed class HetznerApiTests : IDisposable
{
    private static CancellationToken Test => TestContext.Current.CancellationToken;

    // a stand-in token, as long as Hetzner's: no test ever uses a real one
    private const string Token = "hzTestToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";

    private readonly string _savedRoot = HetznerApi.BaseUrl;
    private readonly TimeSpan _savedPoll = HetznerApi.PollInterval;

    public HetznerApiTests() => HetznerApi.PollInterval = TimeSpan.FromMilliseconds(10);

    public void Dispose()
    {
        HetznerApi.BaseUrl = _savedRoot;
        HetznerApi.PollInterval = _savedPoll;
    }

    private static HetznerApi Client(MockHttp mock)
    {
        HetznerApi.BaseUrl = mock.Root + "/v1";
        return HetznerApi.Create(Token, null, null, null);
    }

    private static string Error(string code, string message) => new JsonObject { ["error"] = new JsonObject { ["code"] = code, ["message"] = message } }.ToJsonString();

    [Fact]
    public async Task The_token_goes_in_the_authorization_header_only()
    {
        using var mock = new MockHttp(_ => MockHttp.Response.Json("{\"servers\":[],\"meta\":{\"pagination\":{\"next_page\":null}}}"));
        using var api = Client(mock);
        var r = await api.GetAsync("/servers", Test);
        Assert.True(r.Success);
        var req = Assert.Single(mock.Requests);
        Assert.Equal("Bearer " + Token, req.Authorization);
        Assert.DoesNotContain(Token, req.Path, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_token_is_reported_as_such_without_the_token()
    {
        // an answer that repeats the token must not bring it into the error text
        using var mock = new MockHttp(_ => MockHttp.Response.Json(Error("unauthorized", "unable to authenticate with token " + Token), 401));
        using var api = Client(mock);
        var r = await api.GetAsync("/servers", Test);
        Assert.False(r.Success);
        Assert.True(r.AuthFailed);
        Assert.False(r.ReadOnly);
        Assert.Equal(401, r.Status);
        Assert.Contains("doesn't accept this token", r.Error, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_read_only_token_says_where_to_make_a_read_and_write_one()
    {
        using var mock = new MockHttp(_ => MockHttp.Response.Json(Error("forbidden", "insufficient permissions for this request"), 403));
        using var api = Client(mock);
        var r = await api.PostAsync("/servers/42/actions/reboot", null, Test);
        Assert.False(r.Success);
        Assert.True(r.ReadOnly);
        Assert.False(r.AuthFailed);
        Assert.Equal("forbidden", r.Code);
        Assert.Contains("Security → API tokens", r.Error, StringComparison.Ordinal);
        Assert.Contains("Read & Write", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Another_403_is_not_taken_for_a_read_only_token()
    {
        using var mock = new MockHttp(_ => MockHttp.Response.Json(Error("resource_limit_exceeded", "project limit exceeded"), 403));
        using var api = Client(mock);
        var r = await api.PostAsync("/zones", new JsonObject { ["name"] = "example.com", ["mode"] = "primary" }, Test);
        Assert.False(r.ReadOnly);
        Assert.Contains("project limit exceeded (resource_limit_exceeded)", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_list_is_read_across_its_pages()
    {
        using var mock = new MockHttp(req =>
        {
            string page = req.Path.Contains("page=2", StringComparison.Ordinal) ? "2" : "1";
            return page == "1"
                ? MockHttp.Response.Json("{\"servers\":[{\"id\":1,\"name\":\"a\"},{\"id\":2,\"name\":\"b\"}],\"meta\":{\"pagination\":{\"page\":1,\"next_page\":2,\"last_page\":2}}}")
                : MockHttp.Response.Json("{\"servers\":[{\"id\":3,\"name\":\"c\"}],\"meta\":{\"pagination\":{\"page\":2,\"next_page\":null,\"last_page\":2}}}");
        });
        using var api = Client(mock);
        var r = await api.GetAllAsync("/servers", "servers", Test);
        Assert.True(r.Success);
        Assert.False(r.Truncated);
        Assert.Equal(new long?[] { 1, 2, 3 }, r.Items.Select(i => CfJson.Long(i["id"])).ToArray());
        Assert.Equal(2, mock.Requests.Count);
        Assert.All(mock.Requests, q => Assert.Contains("per_page=50", q.Path, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_list_stops_at_the_page_cap_and_says_so()
    {
        // every page claims there is another one
        using var mock = new MockHttp(req => MockHttp.Response.Json("{\"zones\":[{\"id\":1}],\"meta\":{\"pagination\":{\"next_page\":" + (mock_page(req) + 1) + "}}}"));
        using var api = Client(mock);
        var r = await api.GetAllAsync("/zones", "zones", Test, maxPages: 3);
        Assert.True(r.Success);
        Assert.True(r.Truncated);
        Assert.Equal(3, mock.Requests.Count);

        static int mock_page(MockHttp.Request req)
        {
            int at = req.Path.IndexOf("page=", req.Path.IndexOf("per_page=", StringComparison.Ordinal) + 9, StringComparison.Ordinal);
            return int.Parse(req.Path[(at + 5)..].Split('&')[0]);
        }
    }

    [Fact]
    public async Task A_rate_limited_request_is_retried_after_a_short_wait()
    {
        int calls = 0;
        using var mock = new MockHttp(_ => Interlocked.Increment(ref calls) == 1
            ? new MockHttp.Response(429, Error("rate_limit_exceeded", "rate limit exceeded"), new Dictionary<string, string> { ["Retry-After"] = "0" })
            : MockHttp.Response.Json("{\"servers\":[]}"));
        using var api = Client(mock);
        var r = await api.GetAsync("/servers", Test);
        Assert.True(r.Success, r.Error);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task The_rate_limit_reset_time_is_used_when_there_is_no_retry_after()
    {
        int calls = 0;
        using var mock = new MockHttp(_ => Interlocked.Increment(ref calls) == 1
            ? new MockHttp.Response(429, Error("rate_limit_exceeded", "rate limit exceeded"),
                                    new Dictionary<string, string> { ["RateLimit-Limit"] = "3600", ["RateLimit-Remaining"] = "0",
                                                                     ["RateLimit-Reset"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString() })
            : MockHttp.Response.Json("{\"zones\":[]}"));
        using var api = Client(mock);
        var r = await api.GetAsync("/zones", Test);
        Assert.True(r.Success, r.Error);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task A_rate_limit_that_lasts_is_reported_after_a_few_tries()
    {
        using var mock = new MockHttp(_ => new MockHttp.Response(429, Error("rate_limit_exceeded", "rate limit exceeded"),
                                                                 new Dictionary<string, string> { ["Retry-After"] = "0" }));
        using var api = Client(mock);
        var r = await api.GetAsync("/servers", Test);
        Assert.False(r.Success);
        Assert.Equal(429, r.Status);
        Assert.Equal(3, mock.Requests.Count);
        Assert.Contains("3600 requests an hour", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_running_action_is_followed_until_it_succeeds()
    {
        int polls = 0;
        using var mock = new MockHttp(req =>
        {
            Assert.Equal("/v1/servers/actions/77", req.Path);
            int n = Interlocked.Increment(ref polls);
            string status = n < 3 ? "running" : "success";
            return MockHttp.Response.Json($"{{\"action\":{{\"id\":77,\"command\":\"reboot\",\"status\":\"{status}\",\"progress\":{n * 40},\"error\":null}}}}");
        });
        using var api = Client(mock);
        var seen = new List<int>();
        var start = new HzAction { Id = 77, Command = "reboot", Status = "running" };
        var done = await api.WaitActionAsync("servers", start, a => seen.Add(a.Progress), Test);
        Assert.True(done.Ok);
        Assert.False(done.StillRunning);
        Assert.Equal(3, polls);
        Assert.Equal(new[] { 0, 40, 80, 100 }, seen.Select(p => Math.Min(p, 100)).ToArray());
    }

    [Fact]
    public async Task A_failed_action_brings_its_reason()
    {
        using var mock = new MockHttp(_ => MockHttp.Response.Json(
            "{\"action\":{\"id\":9,\"command\":\"set_records\",\"status\":\"error\",\"progress\":100,\"error\":{\"code\":\"invalid_input\",\"message\":\"record value is not valid\"}}}"));
        using var api = Client(mock);
        var done = await api.WaitActionAsync("zones", new HzAction { Id = 9, Status = "running" }, null, Test);
        Assert.False(done.Ok);
        Assert.False(done.StillRunning);
        Assert.Contains("record value is not valid (invalid_input)", done.Error, StringComparison.Ordinal);
        Assert.Equal("/v1/zones/actions/9", Assert.Single(mock.Requests).Path);
    }

    [Fact]
    public async Task A_redirect_is_not_followed()
    {
        int elsewhere = 0;
        using var other = new MockHttp(_ => { Interlocked.Increment(ref elsewhere); return MockHttp.Response.Json("{}"); });
        using var mock = new MockHttp(_ => new MockHttp.Response(302, "", new Dictionary<string, string> { ["Location"] = other.Root + "/v1/servers" }));
        using var api = Client(mock);
        var r = await api.GetAsync("/servers", Test);
        Assert.False(r.Success);
        Assert.Equal(302, r.Status);
        Assert.Equal(0, elsewhere);
    }

    [Fact]
    public async Task No_error_path_shows_the_token()
    {
        // nothing listens on this port: a connection error
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        HetznerApi.BaseUrl = $"http://127.0.0.1:{port}/v1";
        using (var api = HetznerApi.Create(Token, null, null, null))
        {
            var r = await api.GetAsync("/servers", Test);
            Assert.False(r.Success);
            Assert.DoesNotContain(Token, r.Error, StringComparison.Ordinal);
        }

        // an answer that isn't JSON, and field errors that quote the token
        using var mock = new MockHttp(req => req.Path.Contains("html", StringComparison.Ordinal)
            ? new MockHttp.Response(502, "<html>" + Token + "</html>")
            : MockHttp.Response.Json("{\"error\":{\"code\":\"invalid_input\",\"message\":\"bad " + Token + "\",\"details\":{\"fields\":[{\"name\":\"token\",\"messages\":[\"" + Token + " is wrong\"]}]}}}", 422));
        using var api2 = Client(mock);
        foreach (var path in new[] { "/html", "/zones" })
        {
            var r = await api2.GetAsync(path, Test);
            Assert.False(r.Success);
            Assert.DoesNotContain(Token, r.Error, StringComparison.Ordinal);
        }

        // a token that can't be one: the message doesn't repeat it either
        var ex = Assert.Throws<ArgumentException>(() => HetznerApi.Create("abc def" + Token, null, null, null));
        Assert.DoesNotContain(Token, ex.Message, StringComparison.Ordinal);
        // nor does the proxy password, or a proxy address with a password in it
        using var withProxy = HetznerApi.Create(Token, "http://user:pr0xyPassw0rd@127.0.0.1:" + port, "user", "pr0xyPassw0rd");
        var rp = await withProxy.GetAsync("/servers", Test);
        Assert.DoesNotContain("pr0xyPassw0rd", rp.Error, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, rp.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void The_api_root_can_only_be_the_real_one_or_loopback()
    {
        Assert.Throws<ArgumentException>(() => HetznerApi.BaseUrl = "https://api.hetzner.cloud.example.net/v1");
        Assert.Throws<ArgumentException>(() => HetznerApi.BaseUrl = "http://192.0.2.1/v1");
        HetznerApi.BaseUrl = "http://127.0.0.1:9/v1";
        HetznerApi.BaseUrl = HetznerApi.DefaultBaseUrl;
        Assert.Equal("https://api.hetzner.cloud/v1", HetznerApi.BaseUrl);
    }

    [Theory]
    [InlineData("@", true)]
    [InlineData("www", true)]
    [InlineData("a.b-c_d", true)]
    [InlineData("*", true)]
    [InlineData("*.dev", true)]
    [InlineData("_acme-challenge.www", true)]
    [InlineData("xn--4bi", true)]
    [InlineData("WWW", false)]          // the API's names are lower case
    [InlineData("www.", false)]
    [InlineData("a..b", false)]
    [InlineData("dev.*", false)]        // a wildcard only as the leftmost label
    [InlineData("a/b", false)]
    [InlineData("../servers", false)]
    [InlineData("a b", false)]
    [InlineData("a?b", false)]
    [InlineData("a%2Fb", false)]
    [InlineData("", false)]
    public void Record_set_names_are_checked(string name, bool ok) => Assert.Equal(ok, HetznerApi.IsRrName(name));

    [Fact]
    public void Record_set_paths_hold_only_checked_parts()
    {
        Assert.Equal("/zones/12/rrsets/www/A", HetznerApi.RrsetPath(12, "www", "A"));
        Assert.Equal("/zones/12/rrsets/@/MX", HetznerApi.RrsetPath(12, "@", "MX"));
        Assert.Equal("/zones/12/rrsets/%2A.dev/AAAA", HetznerApi.RrsetPath(12, "*.dev", "AAAA"));
        Assert.Throws<ArgumentException>(() => HetznerApi.RrsetPath(12, "www", "a"));
        Assert.Throws<ArgumentException>(() => HetznerApi.RrsetPath(12, "www", "SPF"));
        Assert.Throws<ArgumentException>(() => HetznerApi.RrsetPath(12, "../../servers", "A"));
        Assert.Throws<ArgumentException>(() => HetznerApi.RrsetPath(0, "www", "A"));
        Assert.Throws<ArgumentException>(() => HetznerApi.ServerPath(-1));
        Assert.Throws<ArgumentException>(() => HetznerApi.ZonePath(9007199254740992));
        Assert.Throws<ArgumentException>(() => HetznerApi.ActionPath("volumes", 1));
        Assert.Equal("/servers/actions/5", HetznerApi.ActionPath("servers", 5));
    }

    [Theory]
    [InlineData("", "@")]
    [InlineData("@", "@")]
    [InlineData("example.com", "@")]
    [InlineData("Example.COM.", "@")]
    [InlineData("WWW", "www")]
    [InlineData("www.example.com", "www")]
    [InlineData("www.example.com.", "www")]
    [InlineData("a.b.example.com", "a.b")]
    [InlineData("mail.example.org", "mail.example.org")]   // another domain's name stays as typed (relative to this zone)
    public void Typed_names_become_the_api_spelling(string typed, string expected)
        => Assert.Equal(expected, HetznerApi.NormalizeRrName(typed, "example.com", out _));

    [Theory]
    [InlineData("ex ample")]
    [InlineData("bücher")]
    [InlineData("a..b")]
    public void Names_that_cant_be_one_are_refused_with_a_reason(string typed)
    {
        Assert.Null(HetznerApi.NormalizeRrName(typed, "example.com", out string error));
        Assert.NotEmpty(error);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("Example.COM.", "example.com")]
    [InlineData("xn--bcher-kva.de", "xn--bcher-kva.de")]
    [InlineData("com", null)]
    [InlineData("https://example.com", null)]
    [InlineData("-a.com", null)]
    [InlineData("a_b.com", null)]
    public void Zone_names_are_checked(string typed, string? expected)
        => Assert.Equal(expected, HetznerApi.NormalizeZoneName(typed, out _));

    [Fact]
    public void Answers_are_clipped_and_control_characters_dropped()
    {
        var server = HzServer.From(JsonNode.Parse("{\"id\":5,\"name\":\"" + new string('x', 500) + "\\u001b[31m\",\"status\":\"running\",\"public_net\":{\"ipv4\":{\"ip\":\"not-an-ip\"}}}"));
        Assert.NotNull(server);
        Assert.True(server!.Name.Length <= 81);
        Assert.DoesNotContain('\u001b', server.Name);
        Assert.Equal(string.Empty, server.Ipv4);   // only a real address goes on to other tools
        Assert.Null(HzServer.From(JsonNode.Parse("{\"id\":0,\"name\":\"zero\"}")));
    }
}
