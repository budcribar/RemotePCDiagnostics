using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace RemotePCDiagnostics.Host;

internal sealed class WebcamPreview
{
    private readonly Image _image = new() { Stretch = Stretch.Uniform };
    private readonly Window _window;
    private volatile bool _closed;
    private int _queued;
    private TimeSpan _nextFrame;

    public WebcamPreview()
    {
        _window = new Window
        {
            Title = "Webcam test preview",
            Width = 360,
            Height = 260,
            Background = Brushes.Black,
            Content = _image,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ShowActivated = false
        };
        _window.Closed += (_, _) => { _closed = true; _image.Source = null; };
        _window.Show();
    }

    public void ShowFrame(byte[] bgra, int width, int height, TimeSpan elapsed)
    {
        if (_closed || elapsed < _nextFrame || Interlocked.Exchange(ref _queued, 1) != 0) return;
        _nextFrame = elapsed + TimeSpan.FromMilliseconds(125);
        var w = Math.Min(320, width);
        var h = Math.Max(1, height * w / width);
        var pixels = new byte[w * h * 4];
        for (var y = 0; y < h; y++)
            for (var x = 0; x < w; x++)
                Buffer.BlockCopy(bgra, ((y * height / h) * width + x * width / w) * 4, pixels, (y * w + x) * 4, 4);
        _ = _window.Dispatcher.InvokeAsync(() =>
        {
            try
            {
                if (!_closed)
                    _image.Source = BitmapSource.Create(w, h, 96, 96, PixelFormats.Bgr32, null, pixels, w * 4);
            }
            finally { Volatile.Write(ref _queued, 0); }
        });
    }

    public void Close() => _ = _window.Dispatcher.InvokeAsync(() =>
    {
        if (!_closed) _window.Close();
    });
}
