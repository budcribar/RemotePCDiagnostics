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
        const shell = document.querySelector('.app[data-rpcd-version]');

        let inControl = null;
        let connection = navigator.onLine ? 'unknown' : 'offline';
        if (window.RemoteControl && typeof window.RemoteControl.getState === 'function') {
            const state = window.RemoteControl.getState();
            if (state) {
                if (navigator.onLine && ['connected', 'connecting', 'reconnecting', 'disconnected'].includes(state.connectionState)) {
                    connection = state.connectionState;
                }
                // RemoteBlazorWebView builds before connectionState still show this notice once the page's stream to the
                // session has closed. The page then keeps its last copy, so the control it had is no longer true.
                if (connection === 'unknown' && !state.restarting && document.getElementById('rbwv-connection-lost')) {
                    connection = 'disconnected';
                }
                if (state.restarting) {
                    if (shell) {
                        shell.dataset.rpcdConnection = connection;
                        shell.dataset.rpcdControl = 'restarting';
                    }
                    for (const el of statuses) {
                        el.dataset.rpcdConnection = connection;
                        el.dataset.rpcdControl = 'restarting';
                        if (el.textContent !== 'Restarting…') {
                            el.textContent = 'Restarting…';
                            el.classList.remove('rbwv-in-control', 'rbwv-remote-control');
                        }
                    }
                    return;
                }
                if (connection === 'connected' || connection === 'unknown') {
                    inControl = state.iHaveControl;
                }
            }
        }

        const control = inControl === true ? 'in-control' : inControl === false ? 'view-only' : 'unknown';
        if (shell) {
            shell.dataset.rpcdConnection = connection;
            shell.dataset.rpcdControl = control;
        }
        for (const el of statuses) {
            el.dataset.rpcdConnection = connection;
            let isLocal = inControl;
            if (isLocal === null) {
                const current = (el.textContent || '').trim();
                if (current.includes('You have control') || current === 'In control' || current.includes('🟢')) {
                    isLocal = true;
                } else if (current.includes('has control') || current === 'Remote control' || current.includes('🔴')) {
                    isLocal = false;
                }
            }

            el.dataset.rpcdControl = control;
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

    function isRemoteDisplay() {
        if (window.RemoteBlazor && typeof window.RemoteBlazor.isOwner === 'boolean') {
            return !window.RemoteBlazor.isOwner;
        }
        if (window.RemoteControl && typeof window.RemoteControl.getState === 'function') {
            const s = window.RemoteControl.getState();
            if (s && typeof s.isOwner === 'boolean') return !s.isOwner;
        }
        if (!document.documentElement.classList.contains('rpd-desktop-host') && !(window.chrome && window.chrome.webview)) {
            return true;
        }
        return false;
    }

    function saveAsFile(filename, content, mimeType) {
        try {
            const type = mimeType || 'text/html;charset=utf-8';
            const blob = new Blob([content], { type: type });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'qa-certificate.html';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 1000);
            return true;
        } catch (e) {
            console.error('saveAsFile failed:', e);
            return false;
        }
    }

    window.saveAsFile = saveAsFile;

    function getControlInfo() {
        const isRemote = isRemoteDisplay();
        let hasRemoteSession = false;
        let technicianHasControl = false;
        let localHasControl = true;

        if (window.RemoteControl && typeof window.RemoteControl.getState === 'function') {
            const state = window.RemoteControl.getState();
            if (state && Array.isArray(state.participants) && state.participants.length > 0) {
                hasRemoteSession = state.participants.some(p => !p.owner);
                const primary = state.participants.find(p => p.primary);
                if (primary) {
                    technicianHasControl = !primary.owner;
                    localHasControl = primary.owner;
                }
            } else if (state && typeof state.iHaveControl === 'boolean') {
                if (state.isOwner) {
                    localHasControl = state.iHaveControl;
                    technicianHasControl = !state.iHaveControl;
                } else {
                    technicianHasControl = state.iHaveControl;
                    localHasControl = !state.iHaveControl;
                }
            }
        }

        if (!hasRemoteSession && document.querySelector('.rbwv-control-status')) {
            hasRemoteSession = true;
        }

        return {
            isRemoteDisplay: isRemote,
            hasRemoteSession: hasRemoteSession,
            technicianHasControl: technicianHasControl,
            localHasControl: localHasControl
        };
    }

    function releaseControlToLocal() {
        if (window.RemoteControl && typeof window.RemoteControl.getState === 'function') {
            const state = window.RemoteControl.getState();
            if (state && Array.isArray(state.participants)) {
                const owner = state.participants.find(p => p.owner);
                if (owner && typeof window.RemoteControl.requestPrimary === 'function') {
                    window.RemoteControl.requestPrimary(owner.id);
                    return true;
                }
            }
        }
        const giveBtn = document.querySelector('.rbwv-control-give');
        if (giveBtn) {
            giveBtn.click();
            return true;
        }
        return false;
    }

    const controlSubscribers = new Set();
    function notifyControlSubscribers() {
        if (controlSubscribers.size === 0) return;
        const info = getControlInfo();
        for (const sub of Array.from(controlSubscribers)) {
            try {
                sub.invokeMethodAsync('OnControlStateChanged', info);
            } catch (e) {
                controlSubscribers.delete(sub);
            }
        }
    }

    window.rpdSession = {
        isRemoteDisplay,
        saveAsFile,
        getControlInfo,
        releaseControlToLocal,
        subscribeControl: (dotNetRef) => {
            controlSubscribers.add(dotNetRef);
            try {
                dotNetRef.invokeMethodAsync('OnControlStateChanged', getControlInfo());
            } catch (e) { }
        },
        unsubscribeControl: (dotNetRef) => {
            controlSubscribers.delete(dotNetRef);
        }
    };

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
    window.addEventListener('online', updateControlStatus);
    window.addEventListener('offline', updateControlStatus);
    function hookControl() {
        if (controlHooked) return;
        if (window.RemoteControl && typeof window.RemoteControl.subscribe === 'function') {
            controlHooked = true;
            try {
                window.RemoteControl.subscribe(() => {
                    updateControlStatus();
                    notifyControlSubscribers();
                });
            } catch (e) { }
        }
    }

    new MutationObserver(() => {
        refresh();
        markDesktopHost();
        updateVoiceStatus();
        updateControlStatus();
        notifyControlSubscribers();
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
