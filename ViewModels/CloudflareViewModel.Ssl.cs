using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// Edge certificates (Zone → SSL and Certificates : Edit):
//   GET   /zones/{id}/ssl/certificate_packs?status=all       the packs, their status and expiry
//   GET / PATCH /zones/{id}/ssl/universal/settings {"enabled"}   Universal SSL (turning it off asks first)
// HSTS lives with the zone settings (security_header) and is saved by .Settings.
public partial class CloudflareViewModel
{
    private async Task EnsureCertificatesAsync(CfZone zone, bool force)
    {
        var certs = ExtrasFor(zone).Certificates;
        if (certs.IsLoading || (certs.IsLoaded && !force) || certs.Universal.IsBusy) return;
        var api = Api(out string error);
        if (api is null) { certs.Error = error; return; }
        int session = _sessionGen;
        certs.IsLoading = true;
        CfListResponse packs;
        CfResponse universal;
        try
        {
            var packsTask = api.GetAllAsync(CloudflareApi.ZonePath(zone.Id) + "/ssl/certificate_packs?status=all", 50,
                                            CfPermission.SslCertificates, _sessionCts.Token, maxPages: 10);
            var universalTask = api.GetAsync(CloudflareApi.ZonePath(zone.Id) + "/ssl/universal/settings", CfPermission.SslCertificates, _sessionCts.Token);
            await Task.WhenAll(packsTask, universalTask);
            packs = packsTask.Result;
            universal = universalTask.Result;
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) certs.IsLoading = false;
        }
        if (session != _sessionGen) return;

        // Both refused for the same reason (usually the permission): one message for the card.
        if (!packs.Success && !universal.Success)
        {
            certs.Error = LoadProblem("Edge certificates need", "Couldn't read the edge certificates: ", packs.Denied, packs.Error,
                                      CfPermission.SslCertificates);
            certs.IsLoaded = true;
            return;
        }
        certs.Error = string.Empty;
        certs.Packs.Clear();
        if (packs.Success)
        {
            certs.PacksError = string.Empty;
            // the Universal certificate first, then the active ones
            foreach (var p in packs.Items.Select(CfCertPack.FromApi).OfType<CfCertPack>()
                                         .OrderBy(p => p.Type == "Universal" ? 0 : 1).ThenByDescending(p => p.IsActive)
                                         .ThenBy(p => p.Type, StringComparer.Ordinal))
                certs.Packs.Add(p);
        }
        else certs.PacksError = "Couldn't list the certificates: " + packs.Error;
        certs.HasPacks = certs.Packs.Count > 0;

        if (universal.Success && CfJson.BoolOrNull(universal.Result?["enabled"]) is bool on)
            certs.Universal.LoadValue(on ? "true" : "false");
        else
        {
            certs.Universal.MarkUnavailable();
            if (!universal.Success) certs.Universal.Error = universal.Error;
        }
        certs.IsLoaded = true;
    }

    private async Task SetUniversalSslAsync(CfZone zone, CfSetting s, string value)
    {
        if (IsLocked || s.IsBusy) { s.Revert(); return; }
        var api = Api(out string error);
        if (api is null) { s.Revert(); s.Error = error; return; }
        int session = _sessionGen;
        bool enable = value == s.OnValue;
        s.IsBusy = true;
        s.Error = string.Empty;
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.ZonePath(zone.Id) + "/ssl/universal/settings", new JsonObject { ["enabled"] = enable },
                                     CfPermission.SslCertificates, _sessionCts.Token);
        }
        catch (OperationCanceledException) { s.IsBusy = false; s.Revert(); return; }
        s.IsBusy = false;
        if (session != _sessionGen) return;
        bool current = SelectedZone?.Id == zone.Id;
        if (!r.Success)
        {
            s.Revert();
            s.Error = PlanText(r, CfPlan.Free);
            if (current) SetError("Universal SSL wasn't changed: " + s.Error);
            return;
        }
        bool now = CfJson.BoolOrNull(r.Result?["enabled"]) ?? enable;
        s.SetValue(now ? "true" : "false");
        if (current)
            SetStatus(now
                ? $"Universal SSL is on for {zone.Name}. A new certificate can take a few minutes to be issued."
                : $"Universal SSL is off for {zone.Name}: its certificates are being removed.");
        // the certificate list changes with it
        _ = EnsureCertificatesAsync(zone, force: true);
    }
}
