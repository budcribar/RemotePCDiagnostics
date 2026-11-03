using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Wpf;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Host;

internal sealed class CopilotHandoff : ICopilotHandoff
{
    public Task<bool> TrySendAsync(string prompt) =>
        Application.Current.Dispatcher.InvokeAsync(() => SendAsync(prompt)).Task.Unwrap();

    private static async Task<bool> SendAsync(string prompt)
    {
        var view = new WebView2();
        var window = new Window { Title = "Microsoft Copilot", Width = 920, Height = 720, Content = view };
        var closed = false;
        var keepOpen = false;
        window.Closed += (_, _) => closed = true;
        window.Show();
        try
        {
            await view.EnsureCoreWebView2Async().WaitAsync(TimeSpan.FromSeconds(15));
            view.CoreWebView2.Navigate("https://copilot.microsoft.com/");
            var deadline = DateTime.UtcNow.AddSeconds(15);
            var quoted = JsonSerializer.Serialize(prompt);
            while (!closed && DateTime.UtcNow < deadline)
            {
                await Task.Delay(500);
                if (closed) return false;
                var result = await view.ExecuteScriptAsync($$"""
                    (() => {
                        if (location.origin !== 'https://copilot.microsoft.com') return false;
                        const input = document.querySelector('textarea#userInput');
                        const send = document.querySelector('button[data-testid="submit-button"], button[aria-label="Send message"]');
                        if (!input || !send || !input.getClientRects().length || !send.getClientRects().length) return false;
                        if (input.value) return false;
                        const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
                        set.call(input, {{quoted}});
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        if (send.disabled || send.getAttribute('aria-disabled') === 'true' || input.value !== {{quoted}}) {
                            set.call(input, '');
                            input.dispatchEvent(new Event('input', { bubbles: true }));
                            return false;
                        }
                        send.click();
                        return true;
                    })()
                    """).WaitAsync(TimeSpan.FromSeconds(3));
                if (result == "true")
                {
                    keepOpen = true;
                    window.Closed += (_, _) => view.Dispose();
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            App.Log($"Copilot handoff unavailable: {ex.GetType().Name}");
        }
        finally
        {
            if (!keepOpen)
            {
                if (!closed) window.Close();
                view.Dispose();
            }
        }
        return false;
    }
}
