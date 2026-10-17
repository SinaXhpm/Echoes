using System;
using System.Globalization;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace Echoes.Views.Controls;

/// <summary>
/// A hex dump drawn directly — offset · hex bytes · ASCII — with as many bytes a line as fit the width (16, 8 or 4),
/// so it never needs a horizontal scroll bar, even on a phone. Shows at most <see cref="MaxBytes"/> bytes (a muted
/// note says how much more there is). Three text runs per dump, no child visuals; colors come from brushes set by
/// styles (design tokens, so a theme switch re-colors it), the font from the inherited text properties.
/// </summary>
public sealed class HexDumpView : Control
{
    public static readonly StyledProperty<byte[]?> DataProperty =
        AvaloniaProperty.Register<HexDumpView, byte[]?>(nameof(Data));

    public static readonly StyledProperty<int> MaxBytesProperty =
        AvaloniaProperty.Register<HexDumpView, int>(nameof(MaxBytes), 4096);

    public static readonly StyledProperty<IBrush?> OffsetBrushProperty =
        AvaloniaProperty.Register<HexDumpView, IBrush?>(nameof(OffsetBrush));
    public static readonly StyledProperty<IBrush?> HexBrushProperty =
        AvaloniaProperty.Register<HexDumpView, IBrush?>(nameof(HexBrush));
    public static readonly StyledProperty<IBrush?> AsciiBrushProperty =
        AvaloniaProperty.Register<HexDumpView, IBrush?>(nameof(AsciiBrush));

    public static readonly StyledProperty<FontFamily> FontFamilyProperty =
        TextElement.FontFamilyProperty.AddOwner<HexDumpView>();
    public static readonly StyledProperty<double> FontSizeProperty =
        TextElement.FontSizeProperty.AddOwner<HexDumpView>();

    private const int OffsetDigits = 4;
    private const string Hex = "0123456789abcdef";

    private double _charW, _lineH;
    private int _bpl = 16;
    private FormattedText? _offsets, _hex, _ascii, _note;

    static HexDumpView()
    {
        AffectsMeasure<HexDumpView>(DataProperty, MaxBytesProperty, FontFamilyProperty, FontSizeProperty);
        AffectsRender<HexDumpView>(OffsetBrushProperty, HexBrushProperty, AsciiBrushProperty);
    }

    public byte[]? Data { get => GetValue(DataProperty); set => SetValue(DataProperty, value); }
    public int MaxBytes { get => GetValue(MaxBytesProperty); set => SetValue(MaxBytesProperty, value); }
    public IBrush? OffsetBrush { get => GetValue(OffsetBrushProperty); set => SetValue(OffsetBrushProperty, value); }
    public IBrush? HexBrush { get => GetValue(HexBrushProperty); set => SetValue(HexBrushProperty, value); }
    public IBrush? AsciiBrush { get => GetValue(AsciiBrushProperty); set => SetValue(AsciiBrushProperty, value); }
    public FontFamily FontFamily { get => GetValue(FontFamilyProperty); set => SetValue(FontFamilyProperty, value); }
    public double FontSize { get => GetValue(FontSizeProperty); set => SetValue(FontSizeProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        var p = change.Property;
        if (p == DataProperty || p == MaxBytesProperty || p == OffsetBrushProperty || p == HexBrushProperty
            || p == AsciiBrushProperty)
            DropTexts();
        else if (p == FontFamilyProperty || p == FontSizeProperty)
        {
            _charW = 0;
            DropTexts();
        }
    }

    private void DropTexts() => _offsets = _hex = _ascii = _note = null;

    private Typeface Face => new(FontFamily ?? FontFamily.Default);

    private FormattedText Text(string s, IBrush? brush)
        => new(s, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Face, FontSize > 0 ? FontSize : 12, brush ?? Brushes.Gray);

    private void EnsureMetrics()
    {
        if (_charW > 0) return;
        var probe = Text("0000000000000000", null);
        _charW = probe.WidthIncludingTrailingWhitespace / 16;
        _lineH = probe.Height;   // not rounded: the runs' own line pitch, or a long dump drifts from its measured height
        if (_charW <= 0) _charW = 7;
        if (_lineH <= 0) _lineH = 15;
    }

    // offset + 2 + hex column + 2 + ascii
    private static int HexChars(int bpl) => bpl * 2 + (bpl - 1) + (bpl / 8 > 1 ? bpl / 8 - 1 : 0);
    private static int LineChars(int bpl) => OffsetDigits + 2 + HexChars(bpl) + 2 + bpl;

    private int PickBytesPerLine(double width)
    {
        if (double.IsInfinity(width) || double.IsNaN(width)) return 16;
        foreach (int bpl in new[] { 16, 8, 4 })
            if (LineChars(bpl) * _charW <= width + 0.5) return bpl;
        return 4;
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var data = Data;
        if (data is null || data.Length == 0) return default;
        EnsureMetrics();
        int bpl = PickBytesPerLine(availableSize.Width);
        if (bpl != _bpl) { _bpl = bpl; DropTexts(); }
        int shown = Math.Min(data.Length, Math.Max(16, MaxBytes));
        int lines = (shown + bpl - 1) / bpl + (shown < data.Length ? 1 : 0);
        double w = LineChars(bpl) * _charW;
        return new Size(double.IsInfinity(availableSize.Width) ? w : Math.Min(w, availableSize.Width), lines * _lineH);
    }

    public override void Render(DrawingContext context)
    {
        var data = Data;
        if (data is null || data.Length == 0) return;
        EnsureMetrics();
        if (_offsets is null) Build(data);
        double x = 0;
        context.DrawText(_offsets!, new Point(x, 0));
        x += (OffsetDigits + 2) * _charW;
        context.DrawText(_hex!, new Point(x, 0));
        x += (HexChars(_bpl) + 2) * _charW;
        context.DrawText(_ascii!, new Point(x, 0));
        if (_note != null) context.DrawText(_note, new Point(0, LinesOf(data) * _lineH));
    }

    private int LinesOf(byte[] data)
    {
        int shown = Math.Min(data.Length, Math.Max(16, MaxBytes));
        return (shown + _bpl - 1) / _bpl;
    }

    private void Build(byte[] data)
    {
        int bpl = _bpl;
        int shown = Math.Min(data.Length, Math.Max(16, MaxBytes));
        int lines = (shown + bpl - 1) / bpl;
        var off = new StringBuilder(lines * (OffsetDigits + 1));
        var hex = new StringBuilder(lines * (HexChars(bpl) + 1));
        var asc = new StringBuilder(lines * (bpl + 1));
        for (int line = 0; line < lines; line++)
        {
            int start = line * bpl;
            if (line > 0) { off.Append('\n'); hex.Append('\n'); asc.Append('\n'); }
            for (int d = OffsetDigits - 1; d >= 0; d--) off.Append(Hex[(start >> (d * 4)) & 0xF]);
            for (int i = 0; i < bpl; i++)
            {
                if (i > 0) hex.Append(i % 8 == 0 && bpl > 8 ? "  " : " ");
                int k = start + i;
                if (k < shown)
                {
                    byte b = data[k];
                    hex.Append(Hex[b >> 4]).Append(Hex[b & 0xF]);
                    asc.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
                }
                else hex.Append("  ");
            }
        }
        _offsets = Text(off.ToString(), OffsetBrush);
        _hex = Text(hex.ToString(), HexBrush);
        _ascii = Text(asc.ToString(), AsciiBrush);
        _note = shown < data.Length
            ? Text($"… {Helpers.SocketPayload.FormatBytes(data.Length - shown)} more not shown (copy or save the transcript for all of it)", OffsetBrush)
            : null;
    }
}
