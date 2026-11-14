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

    function markDesktopHost() {
        if ((window.chrome && window.chrome.webview) || (window.RemoteBlazor && window.RemoteBlazor.isOwner)) {
            document.documentElement.classList.add('rpd-desktop-host');
        }
    }

    function updateVoiceStatus() {
        const statuses = document.querySelectorAll('.rbwv-voice-status');
        for (const el of statuses) {
            const text = (el.textContent || '').trim();
            const isIdle = text === 'Waiting for a voice call';
            if (isIdle) {
                el.classList.add('rbwv-voice-idle');
                el.setAttribute('title', 'Voice ready · Waiting for incoming call');
                el.setAttribute('aria-label', 'Voice ready · Waiting for incoming call');
            } else {
                el.classList.remove('rbwv-voice-idle');
                if (el.getAttribute('title') === 'Voice ready · Waiting for incoming call') {
                    el.removeAttribute('title');
                    el.removeAttribute('aria-label');
                }
            }
        }
    }

    function updateControlStatus() {
        const statuses = document.querySelectorAll('.rbwv-control-status');
        if (statuses.length === 0) return;

        let inControl = null;
        if (window.RemoteControl && typeof window.RemoteControl.getState === 'function') {
            const state = window.RemoteControl.getState();
            if (state) {
                if (state.restarting) {
                    for (const el of statuses) {
                        if (el.textContent !== 'Restarting…') {
                            el.textContent = 'Restarting…';
                            el.classList.remove('rbwv-in-control', 'rbwv-remote-control');
                        }
                    }
                    return;
                }
                inControl = state.iHaveControl;
            }
        }

        for (const el of statuses) {
            let isLocal = inControl;
            if (isLocal === null) {
                const current = (el.textContent || '').trim();
                if (current.includes('You have control') || current === 'In control' || current.includes('🟢')) {
                    isLocal = true;
                } else if (current.includes('has control') || current === 'Remote control' || current.includes('🔴')) {
                    isLocal = false;
                }
            }

            if (isLocal === true) {
                if (el.textContent !== '🟢 In control') {
                    el.textContent = '🟢 In control';
                    el.classList.add('rbwv-in-control');
                    el.classList.remove('rbwv-remote-control');
                    el.title = 'You have control';
                }
            } else if (isLocal === false) {
                if (el.textContent !== '🔴 Remote control') {
                    el.textContent = '🔴 Remote control';
                    el.classList.add('rbwv-remote-control');
                    el.classList.remove('rbwv-in-control');
                    el.title = 'Remote technician has control';
                }
            }
        }
    }

    let voiceHooked = false;
    function hookVoice() {
        if (voiceHooked) return;
        if (window.RemoteVoice && typeof window.RemoteVoice.subscribe === 'function') {
            voiceHooked = true;
            try {
                window.RemoteVoice.subscribe(() => {
                    updateVoiceStatus();
                });
            } catch (e) { }
        }
    }

    let controlHooked = false;
    function hookControl() {
        if (controlHooked) return;
        if (window.RemoteControl && typeof window.RemoteControl.subscribe === 'function') {
            controlHooked = true;
            try {
                window.RemoteControl.subscribe(() => {
                    updateControlStatus();
                });
            } catch (e) { }
        }
    }

    new MutationObserver(() => {
        refresh();
        markDesktopHost();
        updateVoiceStatus();
        updateControlStatus();
        hookVoice();
        hookControl();
    }).observe(document.body, { childList: true, subtree: true, characterData: true });

    refresh();
    markDesktopHost();
    updateVoiceStatus();
    updateControlStatus();
    hookVoice();
    hookControl();
})();
