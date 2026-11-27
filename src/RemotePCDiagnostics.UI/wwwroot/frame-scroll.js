// Keeps the scroll position of a live preview iframe (iframe[data-keep-scroll]) when
// Blazor replaces its srcdoc. Each srcdoc change reloads the frame, which would
// otherwise jump back to the top while a run updates the preview.
(() => {
    const positions = new WeakMap();

    function track(frame) {
        const win = frame.contentWindow;
        if (!win) return;
        const saved = positions.get(frame);
        if (saved) win.scrollTo(saved.x, saved.y);
        win.addEventListener('scroll', () => positions.set(frame, { x: win.scrollX, y: win.scrollY }), { passive: true });
    }

    // load does not bubble, so listen in the capture phase for frames added by any render.
    document.addEventListener('load', e => {
        const frame = e.target;
        if (frame instanceof HTMLIFrameElement && frame.hasAttribute('data-keep-scroll')) {
            try { track(frame); } catch { /* cross-origin frame: nothing to keep */ }
        }
    }, true);
})();
