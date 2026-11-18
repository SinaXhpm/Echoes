using System.Text;
using System.Text.Json.Nodes;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// Dynamic DNS for Hetzner record sets, and the Cloudflare jobs beside them: stand-ins answer for the public-IP services,
/// Hetzner's API and Cloudflare's, and the profile is the test folder's (Support/TestData). A new service over the same
/// profile stands for "Echoes restarted".
/// </summary>
[Collection(HetznerCollection.Name)]
public sealed class HetznerDdnsTests : IDisposable
{
    private static CancellationToken Test => TestContext.Current.CancellationToken;

    private const string Token = "hzDdnsTestToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
    private const string CfToken = "cfDdnsTestToken0123456789abcdefghijklmn";
    private const string CfZone = "0123456789abcdef0123456789abcdef";
    private const string CfRecord = "fedcba9876543210fedcba9876543210";

    // what the stand-ins hold: this device's "public IP", and the Hetzner record set's values
    private volatile string _publicIp = "93.184.216.34";
    private readonly object _gate = new();
    private List<(string Value, string Comment)> _values = new() { ("198.51.100.1", "router") };
    private string _cfContent = "93.184.216.34";
    private readonly MockHttp _mock;
    private readonly string _savedHz = HetznerApi.BaseUrl, _savedCf = CloudflareApi.BaseUrl;
    private readonly TimeSpan _savedPoll = HetznerApi.PollInterval;

    public HetznerDdnsTests()
    {
        _mock = new MockHttp(Handle);
        HetznerApi.BaseUrl = _mock.Root + "/hz";
        CloudflareApi.BaseUrl = _mock.Root + "/cf";
        HetznerApi.PollInterval = TimeSpan.FromMilliseconds(10);
        // two operators agree on the address: the detector's cross-check passes
        DdnsIpDetector.SetTestSources(new[] { "one|" + _mock.Root + "/ip/1", "two|" + _mock.Root + "/ip/2" }, null);
        ProfileService.Instance.Remove(DdnsService.SettingKey);
    }

    public void Dispose()
    {
        ProfileService.Instance.Remove(DdnsService.SettingKey);
        DdnsIpDetector.SetTestSources(null, null);
        HetznerApi.BaseUrl = _savedHz;
        CloudflareApi.BaseUrl = _savedCf;
        HetznerApi.PollInterval = _savedPoll;
        _mock.Dispose();
    }

    private MockHttp.Response Handle(MockHttp.Request req)
    {
        if (req.Path.StartsWith("/ip/", StringComparison.Ordinal)) return new MockHttp.Response(200, _publicIp);
        if (req.Path.StartsWith("/hz/", StringComparison.Ordinal))
        {
            if (req.Authorization != "Bearer " + Token)
                return MockHttp.Response.Json("{\"error\":{\"code\":\"unauthorized\",\"message\":\"unable to authenticate\"}}", 401);
            if (req.Method == "GET" && req.Path == "/hz/zones/7/rrsets/home/A")
            {
                var records = new JsonArray();
                lock (_gate)
                    foreach (var (v, c) in _values) records.Add((JsonNode)new JsonObject { ["value"] = v, ["comment"] = c });
                return MockHttp.Response.Json(new JsonObject
                {
                    ["rrset"] = new JsonObject
                    {
                        ["id"] = "home/A", ["name"] = "home", ["type"] = "A", ["ttl"] = 60, ["records"] = records,
                        ["protection"] = new JsonObject { ["change"] = false }, ["zone"] = 7,
                    },
                }.ToJsonString());
            }
            if (req.Method == "POST" && req.Path == "/hz/zones/7/rrsets/home/A/actions/set_records")
            {
                var body = JsonNode.Parse(req.Body)!["records"]!.AsArray();
                lock (_gate) _values = body.Select(r => (r!["value"]!.GetValue<string>(), r["comment"]?.GetValue<string>() ?? "")).ToList();
                return MockHttp.Response.Json("{\"action\":{\"id\":501,\"command\":\"set_records\",\"status\":\"running\",\"progress\":0,\"error\":null}}", 201);
            }
            if (req.Method == "GET" && req.Path == "/hz/zones/actions/501")
                return MockHttp.Response.Json("{\"action\":{\"id\":501,\"command\":\"set_records\",\"status\":\"success\",\"progress\":100,\"error\":null}}");
            return MockHttp.Response.Json("{\"error\":{\"code\":\"not_found\",\"message\":\"not found\"}}", 404);
        }
        if (req.Path == $"/cf/zones/{CfZone}/dns_records/{CfRecord}")
        {
            if (req.Method == "PATCH")
            {
                _cfContent = JsonNode.Parse(req.Body)!["content"]!.GetValue<string>();
                return MockHttp.Response.Json("{\"success\":true,\"errors\":[],\"result\":{\"type\":\"A\",\"content\":\"" + _cfContent + "\"}}");
            }
            return MockHttp.Response.Json("{\"success\":true,\"errors\":[],\"result\":{\"id\":\"" + CfRecord + "\",\"type\":\"A\",\"content\":\"" + _cfContent + "\"}}");
        }
        return new MockHttp.Response(404, "{}");
    }

    private static DdnsService.Credentials Hetzner() => DdnsService.Credentials.ForHetzner(Token, null, null, null);

    private static DdnsJobInfo Job(DdnsService svc, DdnsProvider provider) => svc.Jobs.Single(j => j.Provider == provider);

    private int SetRecordsCalls => _mock.Count("POST", "/hz/zones/7/rrsets/home/A/actions/set_records");
    private int RrsetReads => _mock.Count("GET", "/hz/zones/7/rrsets/home/A");

    [Fact]
    public async Task A_record_set_is_changed_only_when_the_public_ip_differs()
    {
        var svc = new DdnsService();
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", "198.51.100.1"));

        // the record set holds another address: one set_records with the new one (its comment kept)
        await svc.RunDueAsync(Test, force: true);
        var job = Job(svc, DdnsProvider.Hetzner);
        Assert.Equal(DdnsState.Updated, job.State);
        Assert.Equal(1, SetRecordsCalls);
        var sent = _mock.Requests.Last(r => r.Path.EndsWith("/set_records", StringComparison.Ordinal));
        Assert.Equal("{\"records\":[{\"value\":\"93.184.216.34\",\"comment\":\"router\"}]}", sent.Body);
        Assert.Equal("198.51.100.1", job.PreviousIp);

        // the same address again: nothing is read or written (it was confirmed a moment ago)
        int reads = RrsetReads;
        await svc.RunDueAsync(Test, force: true);
        Assert.Equal(DdnsState.UpToDate, Job(svc, DdnsProvider.Hetzner).State);
        Assert.Equal(reads, RrsetReads);
        Assert.Equal(1, SetRecordsCalls);

        // a new public address: written once more
        _publicIp = "93.184.216.35";
        await svc.RunDueAsync(Test, force: true);
        Assert.Equal(DdnsState.Updated, Job(svc, DdnsProvider.Hetzner).State);
        Assert.Equal(2, SetRecordsCalls);
        lock (_gate) Assert.Equal("93.184.216.35", Assert.Single(_values).Value);
    }

    [Fact]
    public async Task A_record_set_that_already_holds_the_address_is_only_read()
    {
        lock (_gate) _values = new() { ("93.184.216.34", "") };
        var svc = new DdnsService();
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        await svc.RunDueAsync(Test, force: true);
        Assert.Equal(DdnsState.UpToDate, Job(svc, DdnsProvider.Hetzner).State);
        Assert.Equal(1, RrsetReads);
        Assert.Equal(0, SetRecordsCalls);
    }

    [Fact]
    public async Task A_record_set_with_several_values_is_refused_and_left_alone()
    {
        lock (_gate) _values = new() { ("198.51.100.1", ""), ("198.51.100.2", "") };
        var svc = new DdnsService();
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        await svc.RunDueAsync(Test, force: true);
        var job = Job(svc, DdnsProvider.Hetzner);
        Assert.Equal(DdnsState.Error, job.State);
        Assert.Contains("holds 2 values", job.Message, StringComparison.Ordinal);
        Assert.Equal(0, SetRecordsCalls);
        lock (_gate) Assert.Equal(2, _values.Count);
    }

    [Fact]
    public async Task A_refused_token_stops_the_job_without_showing_the_token()
    {
        var svc = new DdnsService();
        var wrong = DdnsService.Credentials.ForHetzner("hzWrongToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL", null, null, null);
        Assert.Null(svc.Add(wrong, "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        await svc.RunDueAsync(Test, force: true);
        var job = Job(svc, DdnsProvider.Hetzner);
        Assert.Equal(DdnsState.Error, job.State);
        Assert.Contains("refused", job.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hzWrongToken", job.Message, StringComparison.Ordinal);
        Assert.Equal(0, SetRecordsCalls);
    }

    [Fact]
    public void Only_a_record_set_of_its_own_type_with_a_checked_name_is_taken()
    {
        var svc = new DdnsService();
        Assert.NotNull(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/AAAA", "home.example.com", "A", null));   // type mismatch
        Assert.NotNull(svc.Add(Hetzner(), "Prod", "7", "example.com", "../x/A", "x", "A", null));
        Assert.NotNull(svc.Add(Hetzner(), "Prod", "007", "example.com", "home/A", "home.example.com", "A", null));     // not the plain number
        Assert.NotNull(svc.Add(Hetzner(), "Prod", CfZone, "example.com", "home/A", "home.example.com", "A", null));
        Assert.NotNull(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/MX", "home.example.com", "MX", null));
        Assert.Empty(svc.Jobs);
    }

    [Fact]
    public void The_saved_jobs_hold_no_token_in_the_clear()
    {
        var svc = new DdnsService();
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        string stored = ProfileService.Instance.GetSetting(DdnsService.SettingKey)!;
        Assert.StartsWith("enc2:", stored, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, stored, StringComparison.Ordinal);
        // inside, the job's credentials are sealed once more
        string json = SecretProtector.Unprotect(stored);
        Assert.DoesNotContain(Token, json, StringComparison.Ordinal);
        var job = JsonNode.Parse(json)!.AsArray().Single()!;
        Assert.Equal("hetzner", job["prov"]!.GetValue<string>());
        Assert.StartsWith("enc2:", job["cred"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- Cloudflare beside it

    // A job list exactly as the build before Hetzner wrote it (no "prov" anywhere).
    private static string OldCloudflareList()
    {
        var cred = new DdnsService.Credentials(true, CfToken, null, null, null, null, null);
        var job = new JsonObject
        {
            ["id"] = "a1b2c3d4e5f60718",
            ["acct"] = "Work",
            ["acctKey"] = cred.AccountKey,
            ["zone"] = CfZone,
            ["zoneName"] = "example.net",
            ["rec"] = CfRecord,
            ["name"] = "home.example.net",
            ["type"] = "A",
            ["cred"] = cred.Seal(),
            ["ip"] = "93.184.216.34",
            ["prev"] = "",
            ["verified"] = 0,
            ["checked"] = 0,
            ["changed"] = 0,
            ["fails"] = 0,
            ["msg"] = "",
            ["state"] = "ok",
        };
        return new JsonArray { (JsonNode)job }.ToJsonString();
    }

    [Fact]
    public async Task Cloudflare_jobs_saved_before_hetzner_load_and_stay_as_they_were()
    {
        string old = OldCloudflareList();
        ProfileService.Instance.SetSetting(DdnsService.SettingKey, SecretProtector.Protect(old));

        var svc = new DdnsService();
        var cf = Assert.Single(svc.Jobs);
        Assert.Equal(DdnsProvider.Cloudflare, cf.Provider);
        Assert.Equal(CfZone, cf.ZoneId);
        Assert.Equal(CfRecord, cf.RecordId);
        Assert.True(svc.Has(CfZone, CfRecord));
        Assert.False(svc.Has(DdnsProvider.Hetzner, CfZone, CfRecord));

        // a Hetzner job comes along: the list is saved again, the Cloudflare job in it unchanged
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        var saved = JsonNode.Parse(SecretProtector.Unprotect(ProfileService.Instance.GetSetting(DdnsService.SettingKey)))!.AsArray();
        var cfSaved = saved.Single(j => j!["zone"]!.GetValue<string>() == CfZone)!.AsObject();
        var cfOld = JsonNode.Parse(old)!.AsArray()[0]!.AsObject();
        Assert.False(cfSaved.ContainsKey("prov"));
        foreach (var key in new[] { "id", "acct", "acctKey", "zone", "zoneName", "rec", "name", "type", "cred", "ip" })
            Assert.Equal(cfOld[key]!.ToJsonString(), cfSaved[key]!.ToJsonString());
        Assert.Equal(cfOld.Select(p => p.Key), cfSaved.Select(p => p.Key));

        // both run: the Cloudflare record already holds the address (read, not written), the Hetzner set is updated
        await svc.RunDueAsync(Test, force: true);
        Assert.Equal(DdnsState.UpToDate, Job(svc, DdnsProvider.Cloudflare).State);
        Assert.Equal(0, _mock.Count("PATCH", "/cf/"));
        Assert.Equal(1, _mock.Count("GET", $"/cf/zones/{CfZone}/dns_records/{CfRecord}"));
        Assert.Equal(DdnsState.Updated, Job(svc, DdnsProvider.Hetzner).State);

        // Echoes restarted on a new public address: the Cloudflare record is changed the Cloudflare way (PATCH content),
        // the Hetzner set with set_records
        _publicIp = "93.184.216.36";
        var restarted = new DdnsService();
        await restarted.RunDueAsync(Test, force: true);
        Assert.Equal(1, _mock.Count("PATCH", $"/cf/zones/{CfZone}/dns_records/{CfRecord}"));
        Assert.Equal("93.184.216.36", _cfContent);
        Assert.Equal(DdnsState.Updated, Job(restarted, DdnsProvider.Cloudflare).State);
        Assert.Equal(DdnsState.Updated, Job(restarted, DdnsProvider.Hetzner).State);
        Assert.Equal(2, SetRecordsCalls);
    }

    [Fact]
    public void Removing_or_editing_one_providers_account_leaves_the_other_alone()
    {
        ProfileService.Instance.SetSetting(DdnsService.SettingKey, SecretProtector.Protect(OldCloudflareList()));
        var svc = new DdnsService();
        Assert.Null(svc.Add(Hetzner(), "Prod", "7", "example.com", "home/A", "home.example.com", "A", null));
        Assert.Equal(2, svc.Jobs.Count);

        // the Hetzner project gets a new token: only its job takes it
        var newer = DdnsService.Credentials.ForHetzner("hzNewerToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL", null, null, null);
        Assert.Equal(1, svc.UpdateAccount(DdnsService.HetznerKeyOf(Token), newer, "Prod"));
        Assert.Equal(newer.AccountKey, Job(svc, DdnsProvider.Hetzner).AccountKey);

        // the project is removed: the Cloudflare job stays
        Assert.Equal(1, svc.RemoveAccount(newer.AccountKey));
        Assert.Equal(DdnsProvider.Cloudflare, Assert.Single(svc.Jobs).Provider);
        Assert.NotEqual(DdnsService.HetznerKeyOf(CfToken), DdnsService.AccountKeyOf(true, CfToken, null, null));
    }
}
