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

    function updateDocumentTitle() {
        const shell = document.querySelector('.app[data-rpcd-machine]');
        const machine = (shell?.dataset.rpcdMachine || document.querySelector('.topbar .pc')?.textContent || '').trim();
        if (machine && document.title !== machine) {
            document.title = machine;
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
                        const bar = el.closest('.rbwv-control-bar');
                        if (bar) syncControlToggle(bar, !isRemoteDisplay(), null, true);
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
            const bar = el.closest('.rbwv-control-bar');
            if (bar) {
                syncControlToggle(bar, !isRemoteDisplay(), isLocal, false);
            }
        }
    }

    function ensureSegmentedSlider(container) {
        if (!container) return;
        let thumb = container.querySelector(':scope > .rpd-seg-thumb');
        if (!thumb) {
            if (container.classList.contains('theme-switch')) return;
            thumb = document.createElement('span');
            thumb.className = 'rpd-seg-thumb';
            thumb.setAttribute('aria-hidden', 'true');
            container.prepend(thumb);
        }
        if (!container.classList.contains('has-thumb')) {
            container.classList.add('has-thumb');
        }

        if (!container.dataset.rpdSwipeBound) {
            container.dataset.rpdSwipeBound = '1';
            let pointerId = null;
            let startX = 0;
            let thumbStartLeft = 0;
            let dragging = false;

            // Watch only button state attributes inside this segmented control so Blazor class="on" updates
            // (clicks, keyboard, initial preference load, remote updates) immediately slide the thumb without
            // re-enabling a document-wide attribute observer.
            new MutationObserver(mutations => {
                if (mutations.some(m => m.target && m.target.tagName === 'BUTTON')) {
                    positionSegmentedThumb(container);
                }
            }).observe(container, { subtree: true, attributes: true, attributeFilter: ['class', 'aria-checked', 'aria-pressed'] });

            if (typeof ResizeObserver !== 'undefined') {
                new ResizeObserver(() => positionSegmentedThumb(container)).observe(container);
            }

            const buttons = () => Array.from(container.querySelectorAll(':scope > button'));
            const bounds = () => {
                const btns = buttons();
                if (!btns.length) return { min: 2, max: 2 };
                const first = btns[0];
                const last = btns[btns.length - 1];
                return { min: first.offsetLeft, max: last.offsetLeft + last.offsetWidth };
            };

            container.addEventListener('pointerdown', e => {
                if (e.button !== 0 && e.pointerType === 'mouse') return;
                const active = container.querySelector(':scope > button.on');
                if (!active) return;
                pointerId = e.pointerId;
                startX = e.clientX;
                thumbStartLeft = active.offsetLeft;
                dragging = false;
            });

            container.addEventListener('pointermove', e => {
                if (pointerId !== e.pointerId) return;
                const dx = e.clientX - startX;
                if (!dragging && Math.abs(dx) < 5) return;
                if (!dragging) {
                    dragging = true;
                    container.classList.add('is-dragging');
                    try { container.setPointerCapture(pointerId); } catch (_) { }
                }
                const t = container.querySelector(':scope > .rpd-seg-thumb');
                if (!t) return;
                const b = bounds();
                const w = t.offsetWidth || 48;
                const x = Math.max(b.min, Math.min(b.max - w, thumbStartLeft + dx));
                t.style.transform = `translateX(${x}px)`;
                e.preventDefault();
            });

            const finishDrag = e => {
                if (pointerId !== e.pointerId) return;
                const wasDragging = dragging;
                pointerId = null;
                dragging = false;
                container.classList.remove('is-dragging');
                if (!wasDragging) return;
                const t = container.querySelector(':scope > .rpd-seg-thumb');
                const center = t ? (new DOMMatrixReadOnly(getComputedStyle(t).transform).m41 + t.offsetWidth / 2) : 0;
                const enabled = buttons().filter(btn => !btn.disabled);
                let best = null;
                let bestDist = Infinity;
                for (const btn of enabled) {
                    const btnCenter = btn.offsetLeft + btn.offsetWidth / 2;
                    const dist = Math.abs(btnCenter - center);
                    if (dist < bestDist) {
                        bestDist = dist;
                        best = btn;
                    }
                }
                if (best && !best.classList.contains('on')) {
                    best.click();
                }
                positionSegmentedThumb(container);
                // Swallow the trailing click synthesized after a drag
                const suppress = ev => { ev.stopPropagation(); ev.preventDefault(); };
                container.addEventListener('click', suppress, { capture: true, once: true });
                setTimeout(() => container.removeEventListener('click', suppress, { capture: true }), 0);
            };

            container.addEventListener('pointerup', finishDrag);
            container.addEventListener('pointercancel', finishDrag);
        }

        positionSegmentedThumb(container);
    }

    function positionSegmentedThumb(container) {
        if (!container || container.classList.contains('is-dragging')) return;
        const thumb = container.querySelector(':scope > .rpd-seg-thumb');
        const active = container.querySelector(':scope > button.on');
        if (!thumb || !active || active.offsetWidth === 0) return;
        thumb.style.width = `${active.offsetWidth}px`;
        thumb.style.transform = `translateX(${active.offsetLeft}px)`;
    }

    function syncSegmentedControls() {
        for (const sw of document.querySelectorAll('.theme-switch, .rpd-control-toggle')) {
            ensureSegmentedSlider(sw);
        }
    }

    // Short restart wording so the bar fits on a phone: "Restart", then "Confirm" / "Cancel" (app.css hides the "Restart the app?" question).
    function relabelRestart(bar) {
        const label = (sel, text) => {
            const el = bar.querySelector(sel);
            if (el && el.textContent !== text) el.textContent = text;
        };
        label(':scope > .rbwv-control-restart', 'Restart');
        label(':scope > .rbwv-control-confirm', 'Confirm');
    }

    // Restart comes first, then the Remote | Local toggle, then the voice call parts.
    function placeToggle(bar, toggle) {
        const restartParts = bar.querySelectorAll(':scope > .rbwv-control-restart, :scope > .rbwv-control-confirm, :scope > .rbwv-control-cancel');
        const after = restartParts.length ? restartParts[restartParts.length - 1] : null;
        if (after) {
            if (after.nextElementSibling !== toggle) after.after(toggle);
        } else if (bar.firstElementChild !== toggle) {
            bar.prepend(toggle);
        }
    }

    function syncControlToggle(bar, isOwner, iHaveControl, restarting) {
        if (!bar) return;
        relabelRestart(bar);
        let toggle = bar.querySelector(':scope > .rpd-control-toggle');
        if (restarting || iHaveControl === null) {
            bar.classList.remove('rpd-has-toggle');
            if (toggle) toggle.hidden = true;
            return;
        }

        const giveBtn = bar.querySelector('.rbwv-control-give');
        const takeBtn = bar.querySelector('.rbwv-control-take');
        const localHasControl = iHaveControl === true;

        if (!toggle) {
            toggle = document.createElement('div');
            toggle.className = 'rpd-control-toggle';
            toggle.setAttribute('role', 'radiogroup');
            toggle.setAttribute('aria-label', 'Control ownership');
            toggle.dataset.testid = 'control-toggle';

            const makeBtn = (side, label) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'rpd-seg-btn';
                btn.setAttribute('role', 'radio');
                btn.dataset.side = side;
                btn.dataset.testid = `control-${side}`;
                const dot = document.createElement('span');
                dot.className = 'rpd-seg-dot';
                dot.setAttribute('aria-hidden', 'true');
                const txt = document.createElement('span');
                txt.textContent = label;
                btn.append(dot, txt);
                btn.addEventListener('click', () => {
                    if (btn.disabled || btn.classList.contains('on')) return;
                    const g = bar.querySelector('.rbwv-control-give');
                    const t = bar.querySelector('.rbwv-control-take');
                    if (side === 'remote') {
                        if (g) g.click();
                    } else if (side === 'local') {
                        if (t) t.click();
                    }
                });
                return btn;
            };

            toggle.append(makeBtn('remote', 'Remote'), makeBtn('local', 'Local'));
        }
        placeToggle(bar, toggle);

        toggle.hidden = false;
        bar.classList.add('rpd-has-toggle');
        toggle.classList.toggle('is-you', localHasControl);
        toggle.classList.toggle('is-other', !localHasControl);

        const remoteBtn = toggle.querySelector('[data-side="remote"]');
        const localBtn = toggle.querySelector('[data-side="local"]');
        if (remoteBtn && localBtn) {
            remoteBtn.classList.toggle('on', !localHasControl);
            remoteBtn.setAttribute('aria-checked', !localHasControl ? 'true' : 'false');
            localBtn.classList.toggle('on', localHasControl);
            localBtn.setAttribute('aria-checked', localHasControl ? 'true' : 'false');

            if (localHasControl) {
                localBtn.disabled = false;
                remoteBtn.disabled = !giveBtn;
                localBtn.title = 'You have control';
                remoteBtn.title = giveBtn
                    ? (isOwner ? 'Give control to remote technician' : 'Give control back to host')
                    : 'No other user connected';
            } else {
                remoteBtn.disabled = false;
                localBtn.disabled = !takeBtn;
                remoteBtn.title = isOwner ? 'Remote technician has control' : 'Host has control';
                localBtn.title = takeBtn ? 'Take control' : 'Waiting for host to give control';
            }
        }

        ensureSegmentedSlider(toggle);
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

    // Opens an HTML page the app built (the client report) in a new tab of whichever browser shows the app: the remote technician's for a
    // remote session. The blob holds only that markup; nothing is fetched or run.
    function openHtml(content) {
        try {
            const url = URL.createObjectURL(new Blob([content], { type: 'text/html;charset=utf-8' }));
            const a = document.createElement('a');
            a.href = url;
            a.target = '_blank';
            a.rel = 'noopener';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 60000);
            return true;
        } catch (e) {
            console.error('openHtml failed:', e);
            return false;
        }
    }

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

    function resolveShopApiTarget(path) {
        const host = (window.location && window.location.hostname || '').toLowerCase();
        if (host === 'remoteblazorwebview.com' || (host.endsWith('.remoteblazorwebview.com') && host !== 'admin.remoteblazorwebview.com')) {
            return { url: 'https://admin.remoteblazorwebview.com' + path, credentials: 'include' };
        }
        return { url: path, credentials: 'same-origin' };
    }

    async function publishQaCertificate(snapshotJson) {
        try {
            const target = resolveShopApiTarget('/api/shop/qa-certificates');
            const res = await fetch(target.url, {
                method: 'POST',
                credentials: target.credentials,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'RemotePCDiagnostics'
                },
                body: snapshotJson
            });
            const text = await res.text();
            let data = null;
            try { data = JSON.parse(text); } catch { }
            return {
                ok: res.ok,
                status: res.status,
                id: data?.id || null,
                url: data?.url || null,
                shortHash: data?.shortHash || null,
                error: data?.error || (res.ok ? null : `HTTP ${res.status}`)
            };
        } catch (e) {
            return {
                ok: false,
                status: 0,
                id: null,
                url: null,
                shortHash: null,
                error: String(e?.message || e || 'Network error')
            };
        }
    }

    async function uploadBenchmark(payloadJson) {
        try {
            const target = resolveShopApiTarget('/api/shop/benchmarks');
            const res = await fetch(target.url, {
                method: 'POST',
                credentials: target.credentials,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'RemotePCDiagnostics'
                },
                body: payloadJson
            });
            const text = await res.text();
            let data = null;
            try { data = JSON.parse(text); } catch { }
            return {
                ok: res.ok,
                status: res.status,
                machineId: data?.machineId || null,
                compareUrl: data?.compareUrl || null,
                computers: typeof data?.computers === 'number' ? data.computers : 0,
                error: data?.error || (res.ok ? null : `HTTP ${res.status}`)
            };
        } catch (e) {
            return {
                ok: false,
                status: 0,
                machineId: null,
                compareUrl: null,
                computers: 0,
                error: String(e?.message || e || 'Network error')
            };
        }
    }

    window.rpdSession = {
        isRemoteDisplay,
        saveAsFile,
        openHtml,
        publishQaCertificate,
        uploadBenchmark,
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

    function bindTopbarPillScroll() {
        for (const strip of document.querySelectorAll('.topbar-pills')) {
            if (strip.dataset.rpdScrollBound) continue;
            strip.dataset.rpdScrollBound = '1';
            strip.addEventListener('scroll', () => {
                window.dispatchEvent(new Event('scroll'));
            }, { passive: true });
        }
    }

    let segSyncQueued = false;
    function scheduleSegmentedSync() {
        if (segSyncQueued) return;
        segSyncQueued = true;
        requestAnimationFrame(() => {
            segSyncQueued = false;
            syncSegmentedControls();
        });
    }

    window.rpdSyncSegmentedControls = syncSegmentedControls;

    document.addEventListener('click', e => {
        if (e.target && e.target.closest && e.target.closest('.theme-switch')) {
            scheduleSegmentedSync();
        }
    }, true);

    window.addEventListener('resize', scheduleSegmentedSync);
    new MutationObserver(() => {
        refresh();
        markDesktopHost();
        updateDocumentTitle();
        updateVoiceStatus();
        updateControlStatus();
        scheduleSegmentedSync();
        bindTopbarPillScroll();
        notifyControlSubscribers();
        hookVoice();
        hookControl();
    }).observe(document.body, { childList: true, subtree: true, characterData: true });

    window.rpdCheckPrefs = {
        load() {
            try { return window.localStorage ? window.localStorage.getItem('rpcd.checkPrefs.v1') : null; }
            catch (_) { return null; }
        },
        save(json) {
            try { if (window.localStorage) window.localStorage.setItem('rpcd.checkPrefs.v1', json || ''); }
            catch (_) { }
        }
    };

    window.rpdScrollTo = function (selector) {
        try {
            const el = document.querySelector(selector);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } catch (_) { }
    };

    window.rpdSetIndeterminate = function (el, value) {
        try { if (el) el.indeterminate = !!value; }
        catch (_) { }
    };

    refresh();
    markDesktopHost();
    updateDocumentTitle();
    updateVoiceStatus();
    updateControlStatus();
    scheduleSegmentedSync();
    bindTopbarPillScroll();
    hookVoice();
    hookControl();
})();

// Pointer test, Drag step: the box follows the pointer here in the page, not through .NET on every move (that lagged behind the
// cursor). .NET still gets the press on the box and the release on a target, which is what the test checks.
(function () {
    let drag = null;
    const end = () => {
        if (!drag) return;
        const el = drag.el;
        drag = null;
        // After the release has been delivered, so the target under the pointer (not the box) gets the pointerup.
        setTimeout(() => {
            el.classList.remove('ptr-dragging');
            el.style.position = el.style.left = el.style.top = el.style.width = '';
        }, 0);
    };
    // The app is zoomed on large screens (.app { zoom }), and an ancestor may be transformed, so a CSS left/top is not the same as a
    // screen position. Measure how the box's left/top map to where it shows (shown = scale * css + offset) and invert that.
    const calibrate = el => {
        el.style.left = '0px'; el.style.top = '0px';
        const a = el.getBoundingClientRect();
        el.style.left = '100px'; el.style.top = '100px';
        const b = el.getBoundingClientRect();
        const sx = (b.left - a.left) / 100 || 1, sy = (b.top - a.top) / 100 || 1;
        return { sx, sy, ox: a.left, oy: a.top };
    };
    const place = (x, y) => {
        drag.el.style.left = ((x - drag.dx - drag.map.ox) / drag.map.sx) + 'px';
        drag.el.style.top = ((y - drag.dy - drag.map.oy) / drag.map.sy) + 'px';
    };
    document.addEventListener('pointerdown', e => {
        const el = e.target instanceof Element ? e.target.closest('.ptr-box') : null;
        if (!el || drag) return;
        const r = el.getBoundingClientRect();
        el.style.width = el.offsetWidth + 'px';
        el.classList.add('ptr-dragging');
        el.style.position = 'fixed';
        drag = { el, id: e.pointerId, dx: e.clientX - r.left, dy: e.clientY - r.top, map: calibrate(el) };
        place(e.clientX, e.clientY);
    }, true);
    document.addEventListener('pointermove', e => {
        if (!drag || e.pointerId !== drag.id) return;
        if (!drag.el.isConnected) { drag = null; return; }
        place(e.clientX, e.clientY);
    }, true);
    document.addEventListener('pointerup', e => { if (drag && e.pointerId === drag.id) end(); }, true);
    document.addEventListener('pointercancel', e => { if (drag && e.pointerId === drag.id) end(); }, true);
})();
