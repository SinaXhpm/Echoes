using System;
using System.Buffers;
using System.Globalization;
using System.IO;
using System.Text;

namespace Echoes.Helpers;

// Pretty-printers multiply their input, and not by a fixed factor: indentation is paid on every line at every level
// (JSON nested 62 deep around 300 K values beautified ×64, XML nested 3,000 deep formatted ×850 — quadratic in the
// depth), so a few hundred KB grew until the process ran out of memory. These writers stop at a ceiling instead: they
// throw the caller's exception the moment the output would pass it. Used by String Lab and the cURL response viewer.

/// <summary>A UTF-8 buffer (for Utf8JsonWriter) that refuses to grow past <c>max</c> bytes.</summary>
internal sealed class CappedBufferWriter : IBufferWriter<byte>
{
    private byte[] _buffer = new byte[16 * 1024];
    private int _written;
    private readonly long _max;
    private readonly Func<Exception> _tooLarge;

    public CappedBufferWriter(long max, Func<Exception> tooLarge)
    {
        _max = max;
        _tooLarge = tooLarge;
    }

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    public void Advance(int count) => _written += count;

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Reserve(sizeHint);
        return _buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Reserve(sizeHint);
        return _buffer.AsSpan(_written);
    }

    private void Reserve(int sizeHint)
    {
        int hint = Math.Max(sizeHint, 1);
        if (_buffer.Length - _written >= hint) return;
        long need = (long)_written + hint;
        if (need > _max) throw _tooLarge();
        Array.Resize(ref _buffer, (int)Math.Max(need, Math.Min((long)_buffer.Length * 2, _max)));
    }
}

/// <summary>The StringWriter an XmlWriter formats into, refusing to grow past <c>max</c> chars.</summary>
internal sealed class CappedStringWriter : StringWriter
{
    private readonly long _max;
    private readonly Func<Exception> _tooLarge;

    public CappedStringWriter(StringBuilder sb, long max, Func<Exception> tooLarge) : base(sb, CultureInfo.InvariantCulture)
    {
        _max = max;
        _tooLarge = tooLarge;
    }

    private void Check(long more)
    {
        if (GetStringBuilder().Length + more > _max) throw _tooLarge();
    }

    public override void Write(char value) { Check(1); base.Write(value); }
    public override void Write(char[] buffer, int index, int count) { Check(count); base.Write(buffer, index, count); }
    public override void Write(ReadOnlySpan<char> buffer) { Check(buffer.Length); base.Write(buffer); }
    public override void Write(string? value) { Check(value?.Length ?? 0); base.Write(value); }
}
