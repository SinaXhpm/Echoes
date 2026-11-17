using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// The lower card's third view: the answers the HTTP checks got in the last run (HTTPS, HTTP, and through the proxy), each
// in the shared response viewer — a block page, an error page, an API's JSON, as it came. Not in the log or the report.
public partial class DoctorViewModel
{
    /// <summary>The last run's answers, in the checks' order (HTTPS first: what a browser would show).</summary>
    public ObservableCollection<HttpResponseViewModel> Responses { get; } = new();
    private readonly List<DoctorCheck> _responseChecks = new();

    [ObservableProperty] private HttpResponseViewModel? _selectedResponse;

    public bool HasResponses => Responses.Count > 0;
    public bool HasManyResponses => Responses.Count > 1;
    public bool ShowChecks => ViewIndex == 0;
    public bool ShowResponse => ViewIndex == 2;

    private void AddResponse(DoctorCheck check, HttpResponseSnapshot response)
    {
        string title = DoctorEngine.IsProxy(check) ? "Through the proxy · " + DoctorEngine.Title(check) : DoctorEngine.Title(check);
        var vm = new HttpResponseViewModel(response, title);
        int at = _responseChecks.IndexOf(check);
        if (at >= 0)
        {
            var old = Responses[at];
            Responses[at] = vm;
            if (ReferenceEquals(SelectedResponse, old)) SelectResponse(vm);
            old.Release();
        }
        else
        {
            at = 0;
            while (at < _responseChecks.Count && _responseChecks[at] < check) at++;
            _responseChecks.Insert(at, check);
            Responses.Insert(at, vm);
        }
        // the first answer is shown; a later one that comes before it in the checks' order takes its place only while
        // the user hasn't picked one
        if (SelectedResponse is null || (at == 0 && !_responsePicked)) SelectResponse(Responses[0]);
        OnResponsesChanged();
    }

    private bool _responsePicked, _selectingResponse;

    private void SelectResponse(HttpResponseViewModel? vm)
    {
        _selectingResponse = true;
        SelectedResponse = vm;
        _selectingResponse = false;
    }

    partial void OnSelectedResponseChanged(HttpResponseViewModel? value)
    {
        if (!_selectingResponse && value is not null) _responsePicked = true;
    }

    private void ClearResponses()
    {
        foreach (var r in Responses) r.Release();
        Responses.Clear();
        _responseChecks.Clear();
        _responsePicked = false;
        SelectResponse(null);
        OnResponsesChanged();
    }

    private void OnResponsesChanged()
    {
        OnPropertyChanged(nameof(HasResponses));
        OnPropertyChanged(nameof(HasManyResponses));
    }
}
