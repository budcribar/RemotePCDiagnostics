namespace RemotePCDiagnostics.Core;

/// <summary>Text for an error a page threw while drawing or handling a click: one line for the person, the full error for the log.</summary>
public static class PageErrors
{
    public const int MaxLogLength = 6000;
    /// <summary>What <see cref="PageOf"/> calls the start page.</summary>
    public const string Home = "home";

    /// <summary>A page's route as a person would say it: "checks" → "Checks", "area/Network" → "Network", "security-audit" → "Security audit".</summary>
    public static string Title(string page)
    {
        var last = page.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        var words = last.Replace('-', ' ').Trim();
        return words.Length == 0 ? "requested" : char.ToUpperInvariant(words[0]) + words[1..];
    }

    /// <summary>The page's route without address, query or fragment ("checks", "area/Network"); "home" for the start page.</summary>
    public static string PageOf(string? uri, string? baseUri)
    {
        var path = uri ?? "";
        if (!string.IsNullOrEmpty(baseUri) && path.StartsWith(baseUri, StringComparison.OrdinalIgnoreCase)) path = path[baseUri.Length..];
        else if (Uri.TryCreate(path, UriKind.Absolute, out var absolute)) path = absolute.AbsolutePath;
        var cut = path.IndexOfAny(['?', '#']);
        if (cut >= 0) path = path[..cut];
        path = path.Trim('/');
        return path.Length == 0 ? Home : path;
    }

    /// <summary>What the person is told: the kind of error and its first line, never a stack trace.</summary>
    public static string Describe(Exception exception)
    {
        var inner = exception is AggregateException { InnerExceptions.Count: 1 } one ? one.InnerExceptions[0] : exception;
        var message = (inner.Message ?? "").Split('\n')[0].Trim();
        if (message.Length > 200) message = message[..199] + "…";
        return message.Length == 0 ? $"{inner.GetType().Name}." : $"{inner.GetType().Name}: {message}{(message.EndsWith('.') ? "" : ".")}";
    }

    /// <summary>The log line: which page, and the whole error with its stack (capped), on one line so log readers keep it together.</summary>
    public static string LogLine(string page, Exception exception)
    {
        var text = exception.ToString().Replace("\r", "").Replace("\n", " | ");
        if (text.Length > MaxLogLength) text = text[..MaxLogLength] + "…";
        return $"Page error on '{page}': {text}";
    }
}
