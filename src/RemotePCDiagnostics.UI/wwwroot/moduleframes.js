// Unsigned modules' own UIs (UnsignedModuleFrame.razor). A frame has an opaque origin (sandbox without allow-same-origin), so a message
// is matched to its frame by the window that sent it, never by origin. The only message accepted is the frame's content height.
window.rpdModuleFrames = (() => {
    const frames = new Map(); // iframe element -> .NET reference
    window.addEventListener('message', e => {
        for (const [frame, dotnet] of frames) {
            if (frame.contentWindow !== e.source) continue;
            const d = e.data;
            if (d && typeof d === 'object' && d.type === 'rpcd-module-height' && typeof d.height === 'number')
                dotnet.invokeMethodAsync('SetHeight', d.height).catch(() => { });
            return;
        }
    });
    return {
        watch: (frame, dotnet) => { if (frame) frames.set(frame, dotnet); },
        unwatch: frame => { frames.delete(frame); },
    };
})();
