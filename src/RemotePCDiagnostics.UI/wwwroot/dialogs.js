// Shared modal behavior, including dialogs added by a remote Blazor render.
(() => {
    const selector = '[role="dialog"][aria-modal="true"]';
    const focusable = 'button, a[href], input, select, textarea, [tabindex]';
    let stack = [];
    const inertBefore = new Map();
    const visible = el => !el.disabled && el.tabIndex >= 0 && !el.closest('[inert]') && el.getClientRects().length > 0;
    const top = () => stack.at(-1)?.dialog;
    const focusFirst = dialog => (Array.from(dialog.querySelectorAll(focusable)).find(visible) || dialog).focus({ preventScroll: true });

    function refresh() {
        const dialogs = Array.from(document.querySelectorAll(selector));
        const removed = stack.filter(item => !dialogs.includes(item.dialog));
        stack = stack.filter(item => dialogs.includes(item.dialog));
        for (const dialog of dialogs) {
            if (!stack.some(item => item.dialog === dialog)) {
                stack.push({ dialog, opener: document.activeElement });
            }
        }
        // Confirmations sit above drawers even when their markup precedes the drawer.
        stack.sort((a, b) => Number(getComputedStyle(a.dialog).zIndex) - Number(getComputedStyle(b.dialog).zIndex));
        const current = top();
        const desired = new Set();
        if (current) {
            for (let branch = current; branch.parentElement; branch = branch.parentElement) {
                for (const sibling of branch.parentElement.children) {
                    if (sibling !== branch && !sibling.matches('script, style, .drawer-backdrop, .svc-modal-backdrop')) desired.add(sibling);
                }
                if (branch.parentElement === document.body) break;
            }
        }
        for (const [el, original] of inertBefore) {
            if (!desired.has(el)) { el.inert = original; inertBefore.delete(el); }
        }
        for (const el of desired) {
            if (!inertBefore.has(el)) inertBefore.set(el, el.inert);
            el.inert = true;
        }
        // Restore the most recently closed opener, or the outer opener if several dialogs closed together.
        const opener = removed[0]?.opener;
        if (opener?.isConnected && !opener.closest('[inert]') && (!current || current.contains(opener))) opener.focus({ preventScroll: true });
        if (current && !current.contains(document.activeElement)) focusFirst(current);
    }
    document.addEventListener('keydown', event => {
        const dialog = top();
        if (!dialog || event.key !== 'Tab') return;
        const controls = Array.from(dialog.querySelectorAll(focusable)).filter(visible);
        const first = controls[0] || dialog, last = controls.at(-1) || dialog;
        if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
            event.preventDefault(); last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
            event.preventDefault(); first.focus();
        }
    }, true);
    document.addEventListener('focusin', event => {
        const dialog = top();
        if (dialog && !dialog.contains(event.target)) focusFirst(dialog);
    });
    new MutationObserver(refresh).observe(document.body, { childList: true, subtree: true });
    refresh();
})();
