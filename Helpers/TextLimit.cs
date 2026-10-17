namespace Echoes.Helpers;

public static class TextLimit
{
    public const int Default = 100_000;

    public static string Cap(string? text, int max = Default)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text ?? string.Empty;
        // Never cut an emoji / surrogate pair in half: the lone high half rendered as a box and went
        // out with COPY as invalid UTF-16 (DisplayCapConverter.Cap guards the same way).
        if (max > 0 && char.IsHighSurrogate(text[max - 1])) max--;
        return text[..max] +
               $"\n\n… [output truncated — showing first {max:N0} of {text.Length:N0} characters]";
    }
}
