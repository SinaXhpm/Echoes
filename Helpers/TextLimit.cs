namespace Echoes.Helpers;

public static class TextLimit
{
    public const int Default = 100_000;

    public static string Cap(string? text, int max = Default)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text ?? string.Empty;
        return text[..max] +
               $"\n\n… [output truncated — showing first {max:N0} of {text.Length:N0} characters]";
    }
}
