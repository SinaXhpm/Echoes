using UIKit;

namespace Echoes.iOS;

public static class Program
{
    // The process entry point of an iOS app: hand control to UIKit with our app delegate.
    private static void Main(string[] args) => UIApplication.Main(args, null, typeof(AppDelegate));
}
