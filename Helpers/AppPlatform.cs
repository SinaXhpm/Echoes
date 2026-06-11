namespace Echoes.Helpers;

/// <summary>
/// Tiny runtime flag so shared views can hide/show desktop-only bits on the mobile
/// shell. Set once at startup (single-view lifetime => mobile) before any view loads.
/// </summary>
public static class AppPlatform
{
    public static bool IsMobile { get; set; }
    public static bool IsDesktop => !IsMobile;
}
