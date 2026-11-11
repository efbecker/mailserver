/* =============================================================================
 * Mail Platform :: utilitários compartilhados (Painel Admin + Webmail)
 * Sem dependências. Nada de innerHTML com dados do servidor: todo conteúdo
 * dinâmico passa por textContent (h()) para evitar XSS.
 * ========================================================================== */
(function () {
    'use strict';

    /**
     * Cria um elemento: h('div.card#id', {onclick: fn, title: 'x'}, filhos...)
     * Filhos podem ser string, número, Node, arrays ou null/false (ignorados).
     */
    function h(tag, attrs, ...children) {
        const m = /^([a-z0-9-]+)?((?:[.#][\w-]+)*)$/i.exec(tag);
        const el = document.createElement((m && m[1]) || 'div');
        if (m && m[2]) {
            for (const part of m[2].match(/[.#][\w-]+/g)) {
                if (part[0] === '.') el.classList.add(part.slice(1));
                else el.id = part.slice(1);
            }
        }
        if (attrs && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) {
            children.unshift(attrs);
            attrs = null;
        }
        for (const [k, v] of Object.entries(attrs || {})) {
            if (v === null || v === undefined || v === false) continue;
            if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
            else if (k === 'class') el.className = v;
            else if (k === 'dataset') Object.assign(el.dataset, v);
            else if (k === 'text') el.textContent = v;
            else if (k === 'value') el.value = v;
            else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'hidden' || k === 'multiple' || k === 'required') el[k] = !!v;
            else el.setAttribute(k, v === true ? '' : String(v));
        }
        append(el, children);
        return el;
    }

    function append(el, children) {
        for (const c of children.flat(Infinity)) {
            if (c === null || c === undefined || c === false) continue;
            el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
        }
        return el;
    }

    function clear(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
        return el;
    }

    /** Esvazia o elemento e acrescenta os filhos (ignora null/false). */
    function fill(el, ...children) {
        return append(clear(el), children);
    }

    const $ = (sel, root) => (root || document).querySelector(sel);
    const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    // ------------------------------------------------------------- API HTTP
    class ApiError extends Error {
        constructor(status, code, message, data) {
            super(message || 'Erro ' + status);
            this.status = status;
            this.code = code;
            this.data = data || {};
        }
    }

    function createApi(base) {
        const state = { csrf: '', onUnauthorized: null };

        async function refreshCsrf() {
            const r = await fetch(base + '/session', { credentials: 'same-origin', cache: 'no-store' });
            const d = await r.json().catch(() => ({}));
            state.csrf = d.csrf || '';
            return d;
        }

        async function request(method, path, body, opts) {
            opts = opts || {};
            const headers = { Accept: 'application/json' };
            let payload;
            if (method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = state.csrf;
            if (body instanceof FormData) {
                payload = body;
            } else if (body !== undefined && body !== null) {
                headers['Content-Type'] = 'application/json';
                payload = JSON.stringify(body);
            }
            const res = await fetch(base + path, {
                method, headers, body: payload, credentials: 'same-origin', cache: 'no-store',
                signal: opts.signal,
            });
            let data = null;
            const ct = res.headers.get('Content-Type') || '';
            if (res.status !== 204) {
                data = ct.includes('application/json') ? await res.json().catch(() => null) : await res.text();
            }
            if (data && typeof data === 'object' && typeof data.csrf === 'string' && data.csrf) state.csrf = data.csrf;
            if (!res.ok) {
                const code = (data && data.error) || 'http_' + res.status;
                const msg = (data && data.message) || ('Erro HTTP ' + res.status);
                if (res.status === 403 && code === 'csrf' && !opts.retried) {
                    await refreshCsrf();
                    return request(method, path, body, Object.assign({}, opts, { retried: true }));
                }
                if (res.status === 401 && state.onUnauthorized && !opts.noAuthRedirect) state.onUnauthorized(msg);
                throw new ApiError(res.status, code, msg, data);
            }
            return data;
        }

        return {
            state,
            refreshCsrf,
            get: (p, o) => request('GET', p, null, o),
            post: (p, b, o) => request('POST', p, b === undefined ? {} : b, o),
            patch: (p, b, o) => request('PATCH', p, b, o),
            del: (p, b, o) => request('DELETE', p, b, o),
        };
    }

    // ------------------------------------------------------------- Toasts
    function toast(message, kind, ms) {
        let box = $('.toasts');
        if (!box) {
            box = h('div.toasts', { role: 'status', 'aria-live': 'polite' });
            document.body.appendChild(box);
        }
        const t = h('div.toast' + (kind ? '.toast-' + kind : ''), message);
        box.appendChild(t);
        setTimeout(() => t.remove(), ms || (kind === 'error' ? 6000 : 3500));
        return t;
    }

    function errorMessage(e) {
        if (e instanceof ApiError) return e.message;
        if (e && e.name === 'AbortError') return 'Operação cancelada';
        return 'Falha de comunicação com o servidor';
    }

    // ------------------------------------------------------------- Modal
    /**
     * modal({title, body: Node, actions: [{label, kind, onClick(close) -> bool|Promise}], wide})
     * Retorna {close, root}. Esc e clique fora fecham (exceto se locked).
     */
    function modal(opts) {
        const previous = document.activeElement;
        const footer = h('div.modal-footer');
        const dialog = h('div.modal' + (opts.wide ? '.modal-wide' : ''), { role: 'dialog', 'aria-modal': 'true', 'aria-label': opts.title },
            h('div.modal-header', h('h2', opts.title), h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', 'aria-label': 'Fechar', onclick: () => close() }, '✕')),
            h('div.modal-body', opts.body),
            (opts.actions || []).length ? footer : null);
        const backdrop = h('div.modal-backdrop', dialog);
        let closed = false;

        function close(result) {
            if (closed) return;
            closed = true;
            document.removeEventListener('keydown', onKey, true);
            backdrop.remove();
            if (previous && previous.focus) previous.focus();
            if (opts.onClose) opts.onClose(result);
        }
        function onKey(e) {
            if (e.key === 'Escape' && !opts.locked) { e.stopPropagation(); close(); }
        }
        for (const a of opts.actions || []) {
            const b = h('button.btn' + (a.kind ? '.btn-' + a.kind : ''), { type: a.submit ? 'submit' : 'button' }, a.label);
            b.addEventListener('click', async () => {
                if (!a.onClick) return close();
                b.disabled = true;
                try {
                    const r = await a.onClick(close);
                    if (r !== false) close(r);
                } catch (e) {
                    toast(errorMessage(e), 'error');
                } finally {
                    b.disabled = false;
                }
            });
            footer.appendChild(b);
        }
        backdrop.addEventListener('mousedown', (e) => { if (e.target === backdrop && !opts.locked) close(); });
        document.addEventListener('keydown', onKey, true);
        document.body.appendChild(backdrop);
        const focusable = dialog.querySelector('input, select, textarea, [contenteditable="true"]') || footer.querySelector('.btn-primary, .btn-danger') || dialog.querySelector('button');
        if (focusable) setTimeout(() => focusable.focus(), 0);
        return { close, root: dialog };
    }

    /** Confirmação simples. Com `typeToConfirm`, exige digitar o texto. */
    function confirmDialog(opts) {
        return new Promise((resolve) => {
            const input = opts.typeToConfirm ? h('input.input', { type: 'text', autocomplete: 'off', spellcheck: 'false' }) : null;
            const body = h('div',
                h('p', opts.message),
                input ? h('div.field', h('label', 'Digite ', h('code', opts.typeToConfirm), ' para confirmar'), input) : null);
            let ok = false;
            modal({
                title: opts.title || 'Confirmar',
                body,
                actions: [
                    { label: 'Cancelar' },
                    {
                        label: opts.confirmLabel || 'Confirmar', kind: opts.danger ? 'danger' : 'primary',
                        onClick: () => {
                            if (input && input.value.trim() !== opts.typeToConfirm) {
                                toast('O texto digitado não confere', 'error');
                                return false;
                            }
                            ok = true;
                            return true;
                        },
                    },
                ],
                onClose: () => resolve(ok ? (input ? input.value.trim() : true) : false),
            });
        });
    }

    // ------------------------------------------------------------- Formatação
    function bytes(n) {
        n = Number(n) || 0;
        const u = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)).toString().replace('.', ',') + ' ' + u[i];
    }

    function parseDate(v) {
        if (!v) return null;
        const d = new Date(typeof v === 'string' ? v.replace(' ', 'T').replace(/\+00$/, '+00:00') : v);
        return isNaN(d.getTime()) ? null : d;
    }

    function dateTime(v) {
        const d = parseDate(v);
        return d ? d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
    }

    /** Data compacta estilo cliente de e-mail: hora (hoje), dia/mês (este ano) ou data. */
    function shortDate(v) {
        const d = parseDate(v);
        if (!d) return '';
        const now = new Date();
        if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
        if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString('pt-BR', { day: '2-digit', month: 'short' }).replace('.', '');
        return d.toLocaleDateString('pt-BR');
    }

    function relative(v) {
        const d = parseDate(v);
        if (!d) return '—';
        const s = Math.round((Date.now() - d.getTime()) / 1000);
        if (s < 60) return 'agora';
        if (s < 3600) return Math.floor(s / 60) + ' min atrás';
        if (s < 86400) return Math.floor(s / 3600) + ' h atrás';
        return Math.floor(s / 86400) + ' d atrás';
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            toast('Copiado para a área de transferência', 'ok', 1800);
        } catch (_) {
            const ta = h('textarea', { value: text });
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); toast('Copiado', 'ok', 1800); } catch (e) { toast('Não foi possível copiar', 'error'); }
            ta.remove();
        }
    }

    function debounce(fn, ms) {
        let t;
        return function (...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), ms); };
    }

    /** Lê um <form> como objeto (checkbox => boolean, number => int). */
    function formData(form) {
        const out = {};
        for (const el of form.elements) {
            if (!el.name || el.disabled) continue;
            if (el.type === 'checkbox') out[el.name] = el.checked;
            else if (el.type === 'number') out[el.name] = el.value === '' ? null : parseInt(el.value, 10);
            else out[el.name] = el.value.trim();
        }
        return out;
    }

    /** Campo de formulário padrão: label + controle + dica. */
    function field(label, control, hint) {
        const id = control.id || ('f_' + Math.random().toString(36).slice(2, 9));
        control.id = id;
        return h('div.field', h('label', { for: id }, label), control, hint ? h('span.hint', hint) : null);
    }

    function setBusy(button, busy, label) {
        if (!button) return;
        if (busy) {
            button.dataset.label = button.textContent;
            button.disabled = true;
            fill(button, h('span.spinner'), ' ', label || 'Aguarde…');
        } else {
            button.disabled = false;
            button.textContent = button.dataset.label || button.textContent;
        }
    }

    window.MP = {
        h, append, clear, fill, $, $$, ApiError, createApi, toast, errorMessage, modal, confirm: confirmDialog,
        bytes, parseDate, dateTime, shortDate, relative, copyText, debounce, formData, field, setBusy,
    };
})();
