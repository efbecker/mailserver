/* =============================================================================
 * Mail Platform :: Webmail (SPA de 3 colunas)
 *
 * Pastas | lista de conversas | leitura. O HTML das mensagens é sanitizado no
 * servidor e exibido num <iframe sandbox> sem scripts, com CSP própria; imagens
 * externas ficam bloqueadas até o usuário pedir. A chave privada da conta nunca
 * chega ao navegador em claro: ela vive cifrada na sessão do servidor e a chave
 * efêmera que a abre fica num cookie HttpOnly.
 * ========================================================================== */
(function () {
    'use strict';

    const { h, clear, fill, $, toast, errorMessage, modal, confirm, bytes, dateTime, shortDate, debounce, field, setBusy } = window.MP;
    const api = window.MP.createApi('/api/webmail');
    const app = document.getElementById('app');

    const FOLDERS = {
        INBOX: { label: 'Caixa de entrada', ico: '📥' },
        STARRED: { label: 'Com estrela', ico: '★' },
        SENT: { label: 'Enviados', ico: '📤' },
        DRAFTS: { label: 'Rascunhos', ico: '📝' },
        ARCHIVE: { label: 'Arquivo', ico: '🗄' },
        SPAM: { label: 'Spam', ico: '⚠' },
        TRASH: { label: 'Lixeira', ico: '🗑' },
    };
    const FOLDER_ORDER = ['INBOX', 'STARRED', 'SENT', 'DRAFTS', 'ARCHIVE', 'SPAM', 'TRASH'];
    const PAGE = 50;
    const POLL_MS = 60000;
    const AUTOSAVE_MS = 20000;
    const SANDBOX = 'allow-same-origin allow-popups allow-popups-to-escape-sandbox';

    const state = {
        me: null,
        folders: {},
        quota: { used: 0, total: 0 },
        folder: 'INBOX',
        filter: null,
        q: '',
        threads: [],
        hasMore: false,
        nextBefore: null,
        loadingList: false,
        selected: null,       // thread_id aberto
        thread: null,         // dados da conversa aberta
        listAbort: null,
    };
    const ui = {};
    let pollTimer = null;
    let composer = null;

    api.state.onUnauthorized = (msg) => {
        if (state.me) {
            state.me = null;
            stopPolling();
            if (composer) composer.destroy(true);
            toast(msg || 'Sessão expirada. Entre novamente.', 'error');
            renderLogin();
        }
    };

    // =====================================================================
    // Login
    // =====================================================================
    async function boot() {
        try {
            const s = await api.refreshCsrf();
            if (s.authenticated) {
                state.me = s;
                renderShell();
            } else {
                renderLogin();
            }
        } catch (e) {
            fill(app, h('div.auth-screen', h('div.auth-card',
                h('h2', 'Webmail indisponível'), h('p', 'Não foi possível contatar o servidor.'),
                h('button.btn.btn-primary', { onclick: boot }, 'Tentar novamente'))));
        }
    }

    function renderLogin() {
        document.title = 'Entrar · Webmail';
        const email = h('input.input', { name: 'email', type: 'email', autocomplete: 'username', required: true, autocapitalize: 'off', spellcheck: 'false' });
        const pass = h('input.input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
        const err = h('div.form-error', { role: 'alert' });
        const btn = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Entrar');
        const form = h('form', { novalidate: true }, field('E-mail', email), field('Senha', pass), err, btn);
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            err.textContent = '';
            if (!email.value.trim() || !pass.value) { err.textContent = 'Informe e-mail e senha.'; return; }
            setBusy(btn, true, 'Desbloqueando caixa…');
            try {
                await api.refreshCsrf();
                await api.post('/login', { email: email.value.trim(), password: pass.value }, { noAuthRedirect: true });
                pass.value = '';
                state.me = await api.refreshCsrf();
                renderShell();
            } catch (ex) {
                err.textContent = errorMessage(ex);
                pass.select();
            } finally {
                setBusy(btn, false);
            }
        });
        fill(app, h('div.auth-screen', h('div.auth-card',
            h('div.auth-brand', h('div.logo', 'MP'), h('div', h('h1', 'Webmail'), h('p.auth-sub', location.hostname))),
            form,
            h('p.auth-note', '🔒', 'Suas mensagens são cifradas com a sua senha. Nem o administrador consegue lê-las.'))));
        setTimeout(() => email.focus(), 0);
    }

    async function logout() {
        if (composer && composer.dirty() && !(await confirm({ title: 'Sair', message: 'Há uma mensagem em edição. Sair mesmo assim?', confirmLabel: 'Sair' }))) return;
        if (composer) composer.destroy(true);
        stopPolling();
        try { await api.post('/logout'); } catch (_) { /* ignora */ }
        state.me = null;
        state.selected = null;
        state.thread = null;
        await api.refreshCsrf().catch(() => null);
        renderLogin();
    }

    // =====================================================================
    // Shell de 3 colunas
    // =====================================================================
    function renderShell() {
        ui.folderList = h('ul.folder-list', { role: 'list' });
        ui.quotaText = h('div.quota-text');
        ui.quotaMeter = h('div.meter', h('span'));
        ui.sidebar = h('aside.mail-sidebar', { 'aria-label': 'Pastas' },
            h('div.brand', h('div.logo', 'MP'), h('strong', 'Webmail')),
            h('button.btn.btn-primary.compose-btn', { type: 'button', title: 'Escrever (c)', onclick: () => openComposer({}) }, '✎', h('span.btn-text', ' Escrever')),
            ui.folderList,
            h('div.account',
                h('div.email', { title: state.me.email }, state.me.full_name || state.me.email),
                h('div.stat-sub', state.me.email),
                ui.quotaText, ui.quotaMeter,
                h('div.btn-group',
                    h('button.btn.btn-sm', { type: 'button', onclick: changePasswordDialog }, 'Alterar senha'),
                    h('button.btn.btn-sm', { type: 'button', onclick: logout }, 'Sair'))));

        ui.search = h('input.input', { type: 'search', placeholder: 'Pesquisar (/)', 'aria-label': 'Pesquisar mensagens', autocomplete: 'off' });
        ui.search.addEventListener('input', debounce(() => { state.q = ui.search.value.trim(); loadThreads(true); }, 350));
        ui.search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { ui.search.value = ''; state.q = ''; loadThreads(true); ui.search.blur(); } });
        ui.listTitle = h('h2');
        ui.listActions = h('div.toolbar');
        ui.chips = h('div.chips', [['unread', 'Não lidas'], ['attachments', 'Com anexo'], ['starred', 'Com estrela']].map(([id, label]) =>
            h('button.chip', { type: 'button', 'aria-pressed': 'false', dataset: { filter: id }, onclick: () => setFilter(id) }, label)));
        ui.threads = h('ul.threads', { role: 'listbox', 'aria-label': 'Conversas', tabindex: '0' });
        ui.listFooter = h('div.list-footer');
        ui.threads.addEventListener('scroll', () => {
            if (state.hasMore && !state.loadingList && ui.threads.scrollTop + ui.threads.clientHeight > ui.threads.scrollHeight - 200) loadThreads(false);
        });
        ui.list = h('section.mail-list', { 'aria-label': 'Lista de conversas' },
            h('div.list-header',
                h('div.list-title',
                    h('button.btn.btn-ghost.btn-icon.mobile-only', { type: 'button', 'aria-label': 'Pastas', onclick: () => ui.sidebar.classList.toggle('open') }, '☰'),
                    ui.listTitle, ui.listActions),
                h('div.search', h('span.ico', { 'aria-hidden': 'true' }, '⌕'), ui.search),
                ui.chips),
            ui.threads, ui.listFooter);

        ui.readerToolbar = h('div.reader-toolbar');
        ui.readerBody = h('div.reader-body');
        ui.reader = h('section.mail-reader', { 'aria-label': 'Leitura' }, ui.readerToolbar, ui.readerBody);
        ui.shell = h('div.mail-shell', ui.sidebar, ui.list, ui.reader);
        fill(app, ui.shell);

        document.addEventListener('click', (e) => {
            if (ui.sidebar.classList.contains('open') && !ui.sidebar.contains(e.target) && !e.target.closest('.mobile-only')) ui.sidebar.classList.remove('open');
        });
        renderReaderEmpty();
        selectFolder(folderFromHash(), true);
        startPolling();
    }

    function folderFromHash() {
        const f = location.hash.replace(/^#/, '').toUpperCase();
        return FOLDERS[f] ? f : 'INBOX';
    }

    window.addEventListener('hashchange', () => {
        if (state.me && folderFromHash() !== state.folder) selectFolder(folderFromHash(), true);
    });

    // =====================================================================
    // Pastas
    // =====================================================================
    async function loadFolders() {
        try {
            const r = await api.get('/folders');
            state.folders = {};
            for (const f of r.folders) state.folders[f.id] = f;
            state.quota = { used: r.used_bytes, total: r.quota_bytes };
            renderFolders();
        } catch (e) { /* silencioso: o próximo poll tenta de novo */ }
    }

    function renderFolders() {
        clear(ui.folderList);
        for (const id of FOLDER_ORDER) {
            const f = state.folders[id] || { unread: 0, total: 0 };
            const count = id === 'DRAFTS' ? f.total : (id === 'SENT' || id === 'TRASH' ? 0 : f.unread);
            ui.folderList.appendChild(h('li', h('button.folder', {
                type: 'button', 'aria-current': id === state.folder ? 'true' : 'false', title: FOLDERS[id].label,
                onclick: () => { ui.sidebar.classList.remove('open'); selectFolder(id); },
            }, h('span.ico', { 'aria-hidden': 'true' }, FOLDERS[id].ico), h('span.name', FOLDERS[id].label), count ? h('span.count', String(count)) : null)));
        }
        const pct = state.quota.total ? Math.min(100, state.quota.used / state.quota.total * 100) : 0;
        ui.quotaText.textContent = bytes(state.quota.used) + ' de ' + bytes(state.quota.total) + ' usados';
        ui.quotaMeter.className = 'meter' + (pct > 90 ? ' danger' : pct > 75 ? ' warn' : '');
        ui.quotaMeter.firstChild.style.width = pct.toFixed(1) + '%';
        const unread = (state.folders.INBOX || {}).unread || 0;
        document.title = (unread ? '(' + unread + ') ' : '') + FOLDERS[state.folder].label + ' · Webmail';
    }

    function selectFolder(id, force) {
        if (id === state.folder && !force) return;
        state.folder = id;
        state.filter = null;
        state.q = '';
        ui.search.value = '';
        if (location.hash.replace(/^#/, '').toUpperCase() !== id) history.replaceState(null, '', '#' + id.toLowerCase());
        closeReader();
        ui.listTitle.textContent = FOLDERS[id].label;
        clear(ui.listActions);
        if (id === 'TRASH' || id === 'SPAM') {
            ui.listActions.appendChild(h('button.btn.btn-sm', { type: 'button', onclick: () => emptyFolder(id) }, id === 'TRASH' ? 'Esvaziar lixeira' : 'Esvaziar spam'));
        }
        ui.listActions.appendChild(h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', title: 'Atualizar', 'aria-label': 'Atualizar', onclick: () => refreshAll() }, '↻'));
        renderChips();
        renderFolders();
        loadFolders();
        loadThreads(true);
    }

    async function emptyFolder(id) {
        if (!(await confirm({ title: 'Esvaziar ' + FOLDERS[id].label, danger: true, confirmLabel: 'Excluir definitivamente', message: 'Todas as mensagens desta pasta serão excluídas para sempre.' }))) return;
        try {
            const r = await api.post('/folders/' + id + '/empty');
            toast(r.purged + ' mensagem(ns) excluída(s)', 'ok');
            refreshAll();
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    function setFilter(id) {
        state.filter = state.filter === id ? null : id;
        renderChips();
        loadThreads(true);
    }

    function renderChips() {
        for (const c of ui.chips.children) c.setAttribute('aria-pressed', c.dataset.filter === state.filter ? 'true' : 'false');
    }

    function refreshAll() {
        loadFolders();
        loadThreads(true, true);
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(async () => {
            if (document.hidden || !state.me) return;
            const before = (state.folders.INBOX || {}).total;
            await loadFolders();
            const after = (state.folders.INBOX || {}).total;
            if (after !== before && state.folder === 'INBOX' && !state.q && ui.threads.scrollTop < 50) loadThreads(true, true);
        }, POLL_MS);
    }

    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // =====================================================================
    // Lista de conversas
    // =====================================================================
    async function loadThreads(reset, keepSelection) {
        if (state.listAbort) state.listAbort.abort();
        const ctrl = new AbortController();
        state.listAbort = ctrl;
        state.loadingList = true;
        if (reset) {
            state.threads = [];
            state.nextBefore = null;
            state.hasMore = false;
            if (!keepSelection) ui.threads.scrollTop = 0;
            fill(ui.listFooter, h('span.spinner'));
            if (!keepSelection) clear(ui.threads);
        } else {
            fill(ui.listFooter, h('span.spinner'));
        }
        const params = new URLSearchParams({ folder: state.folder, limit: String(PAGE) });
        if (state.filter) params.set('filter', state.filter);
        if (state.q) params.set('q', state.q);
        if (!reset && state.nextBefore) params.set('before', state.nextBefore);
        try {
            const r = await api.get('/messages?' + params.toString(), { signal: ctrl.signal });
            if (ctrl !== state.listAbort) return;
            state.threads = reset ? r.threads : state.threads.concat(r.threads);
            state.hasMore = r.has_more;
            state.nextBefore = r.next_before;
            renderThreads();
        } catch (e) {
            if (e.name === 'AbortError') return;
            fill(ui.listFooter, h('span.form-error', errorMessage(e)));
            return;
        } finally {
            if (ctrl === state.listAbort) state.loadingList = false;
        }
        clear(ui.listFooter);
        if (state.hasMore) ui.listFooter.appendChild(h('button.btn.btn-sm', { type: 'button', onclick: () => loadThreads(false) }, 'Carregar mais'));
    }

    function renderThreads() {
        clear(ui.threads);
        if (!state.threads.length) {
            ui.threads.appendChild(h('li.empty', state.q ? 'Nenhuma conversa encontrada para “' + state.q + '”.' : state.filter ? 'Nenhuma conversa com este filtro.' : 'Nenhuma conversa nesta pasta.'));
            return;
        }
        for (const t of state.threads) ui.threads.appendChild(threadRow(t));
    }

    function personLabel(p) {
        if (!p) return '';
        return p.name || p.email;
    }

    function threadRow(t) {
        const outgoing = state.folder === 'SENT' || state.folder === 'DRAFTS';
        const who = outgoing ? 'Para: ' + (t.to || []).map(personLabel).join(', ') : personLabel(t.from);
        const li = h('li.thread' + (t.unread ? '.unread' : ''), {
            role: 'option', tabindex: '-1', 'aria-selected': t.thread_id === state.selected ? 'true' : 'false', dataset: { id: t.thread_id },
            onclick: () => openThread(t),
        },
            h('div.from', who || '(sem remetente)', t.count > 1 ? h('span.count-pill', String(t.count)) : null),
            h('div.meta',
                t.has_attachments ? h('span', { title: 'Com anexo' }, '📎') : null,
                t.starred ? h('span.star-on', { title: 'Com estrela' }, '★') : null,
                h('span.date', { title: dateTime(t.last_at) }, shortDate(t.last_at))),
            h('div.subject', state.folder === 'DRAFTS' ? h('span.badge.badge-danger', 'Rascunho') : null, state.folder === 'DRAFTS' ? ' ' : null, t.subject || '(sem assunto)'),
            h('div.snippet', t.snippet || ''));
        return li;
    }

    function markSelectedRow() {
        for (const li of ui.threads.querySelectorAll('.thread')) {
            const on = li.dataset.id === state.selected;
            li.setAttribute('aria-selected', on ? 'true' : 'false');
            if (on) li.scrollIntoView({ block: 'nearest' });
        }
    }

    function moveSelection(delta) {
        if (!state.threads.length) return;
        let i = state.threads.findIndex((t) => t.thread_id === state.selected);
        i = i < 0 ? 0 : Math.max(0, Math.min(state.threads.length - 1, i + delta));
        openThread(state.threads[i]);
    }

    // =====================================================================
    // Leitura
    // =====================================================================
    function renderReaderEmpty() {
        clear(ui.readerToolbar);
        fill(ui.readerBody, h('div.reader-empty', h('div.big', '✉'), h('div', 'Selecione uma conversa para ler'),
            h('div.stat-sub', 'Atalhos: c escrever · j/k navegar · r responder · e arquivar · # excluir · / pesquisar')));
    }

    function closeReader() {
        state.selected = null;
        state.thread = null;
        ui.shell.classList.remove('reading');
        renderReaderEmpty();
        markSelectedRow();
    }

    async function openThread(t) {
        if (state.folder === 'DRAFTS') {
            openDraft(t.message_id);
            return;
        }
        state.selected = t.thread_id;
        markSelectedRow();
        ui.shell.classList.add('reading');
        clear(ui.readerToolbar);
        fill(ui.readerBody, h('div.loading', h('span.spinner')));
        try {
            const r = await api.get('/threads/' + t.thread_id + '?folder=' + state.folder);
            if (state.selected !== t.thread_id) return;
            state.thread = r;
            if (t.unread) {
                t.unread = false;
                const li = ui.threads.querySelector('[data-id="' + t.thread_id + '"]');
                if (li) li.classList.remove('unread');
                loadFolders();
            }
            renderThread(r);
        } catch (e) {
            if (state.selected !== t.thread_id) return;
            fill(ui.readerBody, h('div.reader-empty', h('div', errorMessage(e)), h('button.btn', { onclick: () => openThread(t) }, 'Tentar novamente')));
        }
    }

    function threadActionButton(label, ico, title, fn) {
        return h('button.btn.btn-ghost.btn-sm', { type: 'button', title, 'aria-label': title, onclick: fn }, ico, label ? ' ' + label : null);
    }

    function renderThread(r) {
        const starred = r.messages.some((m) => m.is_starred);
        const tb = ui.readerToolbar;
        fill(tb, 
            h('button.btn.btn-ghost.btn-icon.btn-sm.mobile-only', { type: 'button', 'aria-label': 'Voltar', onclick: closeReader }, '←'),
            state.folder !== 'ARCHIVE' && state.folder !== 'TRASH' ? threadActionButton('Arquivar', '🗄', 'Arquivar (e)', () => moveThread('ARCHIVE')) : null,
            state.folder === 'SPAM'
                ? threadActionButton('Não é spam', '✓', 'Não é spam', () => moveThread('INBOX'))
                : state.folder !== 'TRASH' ? threadActionButton('Spam', '⚠', 'Marcar como spam', () => moveThread('SPAM')) : null,
            state.folder === 'TRASH'
                ? threadActionButton('Restaurar', '↩', 'Restaurar para a caixa de entrada', () => moveThread('INBOX'))
                : null,
            threadActionButton(state.folder === 'TRASH' || state.folder === 'SPAM' ? 'Excluir para sempre' : 'Excluir', '🗑', 'Excluir (#)', deleteThread),
            threadActionButton('Não lida', '●', 'Marcar como não lida (u)', markUnread),
            threadActionButton(null, starred ? '★' : '☆', starred ? 'Remover estrela (s)' : 'Adicionar estrela (s)', () => toggleStar(!starred)),
            h('span.spacer'),
            moveSelect());

        const body = clear(ui.readerBody);
        body.appendChild(h('h1.thread-subject', r.subject || '(sem assunto)'));
        const last = r.messages.length - 1;
        r.messages.forEach((m, i) => body.appendChild(messageCard(m, i === last || !m.is_read || r.messages.length <= 2)));
        body.scrollTop = 0;
    }

    function moveSelect() {
        const sel = h('select.select', { 'aria-label': 'Mover para', title: 'Mover para' },
            h('option', { value: '' }, 'Mover para…'),
            ['INBOX', 'ARCHIVE', 'SPAM', 'TRASH'].filter((f) => f !== state.folder).map((f) => h('option', { value: f }, FOLDERS[f].label)));
        sel.addEventListener('change', () => { if (sel.value) moveThread(sel.value); });
        return sel;
    }

    function avatarFor(p) {
        const s = (p && (p.name || p.email)) || '?';
        let hash = 0;
        for (const c of s) hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
        const initials = s.replace(/[^\p{L}\p{N} ]/gu, '').trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase() || '?';
        return h('div.avatar.c' + (hash % 8), { 'aria-hidden': 'true' }, initials);
    }

    function recipientsText(m) {
        const parts = [];
        if (m.to.length) parts.push('para ' + m.to.map(personLabel).join(', '));
        if (m.cc.length) parts.push('cc ' + m.cc.map(personLabel).join(', '));
        if (m.bcc && m.bcc.length) parts.push('cco ' + m.bcc.map(personLabel).join(', '));
        return parts.join(' · ');
    }

    function messageCard(m, expanded) {
        const content = h('div.message-content');
        const card = h('article.message' + (expanded ? '' : '.collapsed'), { dataset: { id: m.message_id } },
            h('div.message-head', {
                onclick: (e) => {
                    if (e.target.closest('button, a')) return;
                    card.classList.toggle('collapsed');
                    if (!card.classList.contains('collapsed') && !content.firstChild) fillMessageContent(m, content);
                },
            },
                avatarFor(m.from),
                h('div.who',
                    h('div', h('span.name', m.from.name || m.from.email), m.from.name ? h('span.addr', ' <' + m.from.email + '>') : null),
                    h('div.recips', { title: recipientsText(m) }, recipientsText(m)),
                    h('div.snippet', m.snippet)),
                h('div.when', { title: dateTime(m.date || m.received_at) }, shortDate(m.date || m.received_at),
                    m.attachments.length ? h('div', '📎 ' + m.attachments.length) : null)),
            content);
        if (expanded) fillMessageContent(m, content);
        return card;
    }

    function authBadges(m) {
        if (m.folder === 'SENT' || m.folder === 'DRAFTS') return null;
        const b = (label, ok) => h('span.badge.' + (ok ? 'badge-ok' : 'badge-warn'), { title: label + (ok ? ' aprovado' : ' não aprovado') }, (ok ? '✓ ' : '✕ ') + label);
        return h('div.auth-row',
            b('SPF', m.auth.spf), b('DKIM', m.auth.dkim), b('DMARC', m.auth.dmarc),
            m.auth.spam_score ? h('span.badge' + (m.auth.spam_score >= 6 ? '.badge-danger' : ''), { title: 'Pontuação do Rspamd' }, 'spam ' + m.auth.spam_score.toFixed(1)) : null);
    }

    function fillMessageContent(m, content) {
        const suspicious = m.folder === 'SPAM' || !(m.auth.dkim || m.auth.spf);
        const frame = h('iframe.mail-frame', { sandbox: SANDBOX, title: 'Conteúdo da mensagem', referrerpolicy: 'no-referrer', loading: 'lazy' });
        const imgNotice = h('div.notice', { hidden: true },
            h('span', 'Imagens externas foram bloqueadas para proteger sua privacidade.'),
            h('button.btn.btn-sm', { type: 'button', onclick: () => { imgNotice.hidden = true; loadFrame(true); } }, 'Exibir imagens'));
        let observer = null;

        function resize() {
            try {
                const doc = frame.contentDocument;
                if (!doc || !doc.documentElement) return;
                frame.style.height = Math.max(60, Math.min(doc.documentElement.scrollHeight, 40000)) + 'px';
            } catch (_) { /* origem opaca: mantém altura */ }
        }

        function loadFrame(images) {
            frame.src = '/api/webmail/render/' + m.message_id + (images ? '?images=1' : '');
        }

        frame.addEventListener('load', () => {
            try {
                const doc = frame.contentDocument;
                resize();
                if (observer) observer.disconnect();
                if (window.ResizeObserver && doc && doc.body) {
                    observer = new ResizeObserver(resize);
                    observer.observe(doc.body);
                }
                if (doc) {
                    for (const img of doc.images) img.addEventListener('load', resize);
                    if (!frame.src.includes('images=1') && doc.querySelector('[data-mp-blocked]')) imgNotice.hidden = false;
                    // Links abrem fora do iframe (rel=noopener definido pelo servidor)
                    doc.addEventListener('click', (e) => {
                        const a = e.target.closest && e.target.closest('a[href^="mailto:"]');
                        if (a) {
                            e.preventDefault();
                            openComposer({ to: decodeURIComponent(a.getAttribute('href').slice(7).split('?')[0]) });
                        }
                    });
                }
            } catch (_) { /* ignora */ }
        });
        window.addEventListener('resize', debounce(resize, 150));

        const attachments = m.attachments.length ? h('div.attachments', m.attachments.map((a) =>
            h('a.attachment', { href: '/api/webmail/attachments/' + encodeURIComponent(a.id), download: a.name, title: a.name + ' · ' + a.mime },
                h('span', { 'aria-hidden': 'true' }, iconFor(a.mime)), h('span.att-name', a.name), h('span.att-size', bytes(a.size))))) : null;

        const raw = h('pre.raw-headers', { hidden: true }, m.raw_headers || '');
        const actions = h('div.message-actions',
            h('button.btn.btn-sm', { type: 'button', onclick: () => reply(m, false) }, '↩ Responder'),
            (m.to.length + m.cc.length > 1) ? h('button.btn.btn-sm', { type: 'button', onclick: () => reply(m, true) }, '↩↩ Responder a todos') : null,
            h('button.btn.btn-sm', { type: 'button', onclick: () => forward(m) }, '↪ Encaminhar'),
            h('button.btn.btn-sm.btn-ghost', { type: 'button', onclick: () => { raw.hidden = !raw.hidden; } }, 'Cabeçalhos'),
            h('button.btn.btn-sm.btn-ghost', { type: 'button', onclick: () => deleteMessage(m) }, 'Excluir esta'));

        fill(content, 
            authBadges(m),
            suspicious && m.folder !== 'SENT' && m.folder !== 'DRAFTS' ? h('div.notice.notice-danger', m.folder === 'SPAM' ? 'Esta mensagem foi classificada como spam. Cuidado com links e anexos.' : 'O remetente não foi autenticado (SPF/DKIM). Confirme a origem antes de confiar no conteúdo.') : null,
            imgNotice, frame, attachments, raw, actions);
        loadFrame(false);
    }

    function iconFor(mime) {
        if (/^image\//.test(mime)) return '🖼';
        if (/pdf/.test(mime)) return '📕';
        if (/zip|compressed|tar|rar|7z/.test(mime)) return '🗜';
        if (/spreadsheet|excel|csv/.test(mime)) return '📊';
        if (/word|document|text/.test(mime)) return '📄';
        if (/rfc822/.test(mime)) return '✉';
        return '📎';
    }

    // ------------------------------------------------------------ Ações
    function removeThreadFromList(id) {
        const i = state.threads.findIndex((t) => t.thread_id === id);
        if (i >= 0) state.threads.splice(i, 1);
        const li = ui.threads.querySelector('[data-id="' + id + '"]');
        const next = li && (li.nextElementSibling || li.previousElementSibling);
        if (li) li.remove();
        if (!state.threads.length) renderThreads();
        return next && next.dataset && next.dataset.id ? state.threads.find((t) => t.thread_id === next.dataset.id) : null;
    }

    async function moveThread(folder) {
        const id = state.selected;
        if (!id) return;
        try {
            await api.patch('/threads/' + id, { folder, from_folder: state.folder });
            toast('Conversa movida para ' + FOLDERS[folder].label, 'ok', 2200);
            afterRemoval(id);
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    async function deleteThread() {
        const id = state.selected;
        if (!id) return;
        const permanent = state.folder === 'TRASH' || state.folder === 'SPAM';
        if (permanent && !(await confirm({ title: 'Excluir para sempre', danger: true, confirmLabel: 'Excluir', message: 'A conversa será apagada definitivamente.' }))) return;
        try {
            const r = await api.del('/threads/' + id + '?folder=' + state.folder);
            toast(r.purged ? 'Conversa excluída definitivamente' : 'Conversa movida para a lixeira', 'ok', 2200);
            afterRemoval(id);
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    async function deleteMessage(m) {
        try {
            const r = await api.del('/messages/' + m.message_id);
            toast(r.purged ? 'Mensagem excluída definitivamente' : 'Mensagem movida para a lixeira', 'ok', 2200);
            if (state.thread && state.thread.messages.length > 1) {
                const t = state.threads.find((x) => x.thread_id === state.selected);
                if (t) openThread(t);
            } else {
                afterRemoval(state.selected);
            }
            loadFolders();
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    function afterRemoval(id) {
        const next = removeThreadFromList(id);
        loadFolders();
        if (next && window.innerWidth > 760) openThread(next);
        else closeReader();
    }

    async function markUnread() {
        const id = state.selected;
        if (!id) return;
        try {
            await api.patch('/threads/' + id, { is_read: false, from_folder: state.folder });
            const t = state.threads.find((x) => x.thread_id === id);
            if (t) t.unread = true;
            closeReader();
            renderThreads();
            loadFolders();
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    async function toggleStar(on) {
        const id = state.selected;
        if (!id) return;
        try {
            await api.patch('/threads/' + id, { is_starred: on, from_folder: state.folder });
            const t = state.threads.find((x) => x.thread_id === id);
            if (t) t.starred = on;
            if (state.thread) state.thread.messages.forEach((m) => { m.is_starred = on; });
            renderThreads();
            markSelectedRow();
            if (state.thread) renderThread(state.thread);
            loadFolders();
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    // =====================================================================
    // Composer
    // =====================================================================
    function addrList(list) {
        return list.map((p) => (p.name && !/[",<>]/.test(p.name) ? p.name + ' <' + p.email + '>' : p.name ? '"' + p.name.replace(/"/g, "'") + '" <' + p.email + '>' : p.email)).join(', ');
    }

    function quoteBlock(m) {
        const wrap = document.createElement('div');
        const head = h('div', 'Em ' + dateTime(m.date || m.received_at) + ', ' + (m.from.name ? m.from.name + ' <' + m.from.email + '>' : m.from.email) + ' escreveu:');
        const bq = h('blockquote');
        for (const line of (m.body_plain || m.snippet || '').split('\n')) bq.append(line, h('br'));
        wrap.append(h('p', h('br')), head, bq);
        return wrap.innerHTML;
    }

    function prefixed(prefix, subject) {
        const re = new RegExp('^\\s*' + prefix + '\\s*:', 'i');
        return re.test(subject || '') ? subject : prefix + ': ' + (subject || '');
    }

    function reply(m, all) {
        const me = state.me.email.toLowerCase();
        const own = m.from.email.toLowerCase() === me;
        let to;
        let cc = [];
        if (own) {
            to = m.to;
            if (all) cc = m.cc;
        } else {
            to = m.reply_to.length ? m.reply_to : [m.from];
            if (all) {
                cc = m.to.concat(m.cc).filter((p) => p.email.toLowerCase() !== me && !to.some((x) => x.email === p.email));
            }
        }
        openComposer({
            to: addrList(to), cc: addrList(cc), subject: prefixed('Re', state.thread ? state.thread.subject : m.subject),
            html: quoteBlock(m), replyTo: m.message_id, title: all ? 'Responder a todos' : 'Responder',
        });
    }

    function forward(m) {
        const head = document.createElement('div');
        const bq = h('blockquote');
        for (const line of (m.body_plain || '').split('\n')) bq.append(line, h('br'));
        head.append(h('p', h('br')),
            h('div', '---------- Mensagem encaminhada ----------'),
            h('div', 'De: ' + (m.from.name ? m.from.name + ' <' + m.from.email + '>' : m.from.email)),
            h('div', 'Data: ' + dateTime(m.date || m.received_at)),
            h('div', 'Assunto: ' + (m.subject || '')),
            h('div', 'Para: ' + addrList(m.to)),
            h('br'), bq);
        openComposer({
            subject: prefixed('Fwd', m.subject), html: head.innerHTML, title: 'Encaminhar',
            carried: { source: m.message_id, list: m.attachments.map((a) => ({ id: a.id, name: a.name, size: a.size })) },
        });
    }

    async function openDraft(messageId) {
        try {
            const m = await api.get('/messages/' + messageId);
            openComposer({
                to: addrList(m.to), cc: addrList(m.cc), bcc: addrList(m.bcc || []), subject: m.subject,
                html: m.draft_html || (m.body_plain ? escapeText(m.body_plain) : ''), draftId: m.message_id, title: 'Rascunho',
                carried: { source: m.message_id, list: m.attachments.map((a) => ({ id: a.id, name: a.name, size: a.size })) },
            });
        } catch (e) { toast(errorMessage(e), 'error'); }
    }

    function escapeText(text) {
        const d = document.createElement('div');
        for (const line of text.split('\n')) d.append(line, h('br'));
        return d.innerHTML;
    }

    async function openComposer(opts) {
        if (composer) {
            if (composer.dirty()) {
                const ok = await confirm({ title: 'Nova mensagem', message: 'Salvar a mensagem atual como rascunho e abrir uma nova?', confirmLabel: 'Salvar e continuar' });
                if (!ok) { composer.focus(); return; }
                await composer.saveDraft(true).catch(() => null);
            }
            composer.destroy(true);
        }
        composer = createComposer(opts || {});
    }

    function createComposer(opts) {
        const draft = { id: opts.draftId || null, replyTo: opts.replyTo || null, carried: opts.carried || null };
        const files = [];
        let dirty = false;
        let saving = null;
        let autosaveTimer = null;

        const toInput = h('input.input', { type: 'text', value: opts.to || '', 'aria-label': 'Para', autocomplete: 'off', spellcheck: 'false' });
        const ccInput = h('input.input', { type: 'text', value: opts.cc || '', 'aria-label': 'Cc', autocomplete: 'off', spellcheck: 'false' });
        const bccInput = h('input.input', { type: 'text', value: opts.bcc || '', 'aria-label': 'Cco', autocomplete: 'off', spellcheck: 'false' });
        const subject = h('input.input', { type: 'text', value: opts.subject || '', 'aria-label': 'Assunto', maxlength: '900' });
        const editor = h('div.editor', { contenteditable: 'true', role: 'textbox', 'aria-multiline': 'true', 'aria-label': 'Mensagem', 'data-placeholder': 'Escreva sua mensagem…', spellcheck: 'true' });
        if (opts.html) editor.innerHTML = opts.html; // HTML montado localmente (textContent) ou sanitizado pelo servidor
        const attList = h('div.composer-attachments');
        const status = h('span.status');
        const fileInput = h('input', { type: 'file', multiple: true, hidden: true });
        const title = h('span.title', opts.title || 'Nova mensagem');
        const sendBtn = h('button.btn.btn-primary', { type: 'button' }, 'Enviar');

        const ccRow = h('div.composer-row', { hidden: !opts.cc }, h('label', 'Cc'), ccInput);
        const bccRow = h('div.composer-row', { hidden: !opts.bcc }, h('label', 'Cco'), bccInput);
        const toRow = h('div.composer-row', h('label', 'Para'), toInput,
            h('div.toggles',
                h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => { ccRow.hidden = false; ccInput.focus(); } }, 'Cc'),
                h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => { bccRow.hidden = false; bccInput.focus(); } }, 'Cco')));

        const cmd = (name, label, ico, arg) => h('button.btn.btn-ghost', {
            type: 'button', title: label, 'aria-label': label,
            onmousedown: (e) => e.preventDefault(),
            onclick: () => {
                let value = arg;
                if (name === 'createLink') {
                    value = window.prompt('Endereço do link (https://…)', 'https://');
                    if (!value || !/^(https?:|mailto:)/i.test(value)) return;
                }
                document.execCommand(name, false, value);
                editor.focus();
                markDirty();
            },
        }, ico);
        const toolbar = h('div.editor-toolbar',
            cmd('bold', 'Negrito', h('strong', 'B')), cmd('italic', 'Itálico', h('em', 'I')), cmd('underline', 'Sublinhado', h('u', 'S')),
            h('span.sep'),
            cmd('insertUnorderedList', 'Lista', '•'), cmd('insertOrderedList', 'Lista numerada', '1.'), cmd('formatBlock', 'Citação', '❝', 'blockquote'),
            h('span.sep'),
            cmd('createLink', 'Inserir link', '🔗'), cmd('removeFormat', 'Limpar formatação', '⌫'));

        const root = h('section.composer', { role: 'dialog', 'aria-label': 'Escrever mensagem' },
            h('div.composer-header', { onclick: (e) => { if (!e.target.closest('button')) root.classList.toggle('minimized'); } },
                title,
                h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', title: 'Minimizar', 'aria-label': 'Minimizar', onclick: () => root.classList.toggle('minimized') }, '▁'),
                h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', title: 'Tela cheia', 'aria-label': 'Tela cheia', onclick: () => root.classList.toggle('maximized') }, '⤢'),
                h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', title: 'Fechar (salva rascunho)', 'aria-label': 'Fechar', onclick: () => close() }, '✕')),
            h('div.composer-body',
                toRow, ccRow, bccRow,
                h('div.composer-row', h('label', 'Assunto'), subject),
                toolbar, editor, attList),
            h('div.composer-footer',
                sendBtn,
                h('button.btn', { type: 'button', title: 'Anexar arquivos', onclick: () => fileInput.click() }, '📎 Anexar'),
                h('button.btn.btn-ghost', { type: 'button', onclick: () => saveDraft(false) }, 'Salvar rascunho'),
                h('button.btn.btn-ghost', { type: 'button', title: 'Descartar', onclick: () => discard() }, '🗑'),
                status, fileInput));
        document.body.appendChild(root);

        // ---------------------------------------------------------- anexos
        function renderAttachments() {
            clear(attList);
            if (draft.carried) {
                for (const a of draft.carried.list) {
                    attList.appendChild(h('span.ip-chip', '📎 ' + a.name + ' (' + bytes(a.size) + ')',
                        h('button.btn.btn-ghost.btn-icon.btn-sm', {
                            type: 'button', 'aria-label': 'Remover ' + a.name,
                            onclick: () => { draft.carried.list = draft.carried.list.filter((x) => x !== a); renderAttachments(); markDirty(); },
                        }, '✕')));
                }
            }
            files.forEach((f, i) => attList.appendChild(h('span.ip-chip', '📎 ' + f.name + ' (' + bytes(f.size) + ')',
                h('button.btn.btn-ghost.btn-icon.btn-sm', { type: 'button', 'aria-label': 'Remover ' + f.name, onclick: () => { files.splice(i, 1); renderAttachments(); markDirty(); } }, '✕'))));
        }

        function addFiles(list) {
            let total = files.reduce((s, f) => s + f.size, 0);
            for (const f of list) {
                total += f.size;
                if (total > 45 * 1048576) { toast('Os anexos somam mais de 45 MB; ' + f.name + ' não foi adicionado.', 'error'); break; }
                files.push(f);
            }
            renderAttachments();
            markDirty();
        }
        fileInput.addEventListener('change', () => { addFiles(Array.from(fileInput.files)); fileInput.value = ''; });
        root.addEventListener('dragover', (e) => { if (e.dataTransfer && Array.from(e.dataTransfer.types).includes('Files')) { e.preventDefault(); root.classList.add('drop-hint'); } });
        root.addEventListener('dragleave', (e) => { if (!root.contains(e.relatedTarget)) root.classList.remove('drop-hint'); });
        root.addEventListener('drop', (e) => {
            if (!e.dataTransfer || !e.dataTransfer.files.length) return;
            e.preventDefault();
            root.classList.remove('drop-hint');
            addFiles(Array.from(e.dataTransfer.files));
        });
        // Colar: apenas texto puro (evita HTML/scripts de outras origens no editor)
        editor.addEventListener('paste', (e) => {
            const items = e.clipboardData ? Array.from(e.clipboardData.files || []) : [];
            if (items.length) { e.preventDefault(); addFiles(items); return; }
            const text = e.clipboardData && e.clipboardData.getData('text/plain');
            if (text !== undefined && text !== null) {
                e.preventDefault();
                document.execCommand('insertText', false, text);
            }
        });
        editor.addEventListener('drop', (e) => { if (e.dataTransfer && !e.dataTransfer.files.length) e.preventDefault(); });

        // ---------------------------------------------------------- estado
        function markDirty() {
            dirty = true;
            status.textContent = '';
            clearTimeout(autosaveTimer);
            autosaveTimer = setTimeout(() => { if (dirty && hasContent()) saveDraft(true).catch(() => null); }, AUTOSAVE_MS);
        }
        for (const el of [toInput, ccInput, bccInput, subject]) el.addEventListener('input', markDirty);
        editor.addEventListener('input', markDirty);

        function hasContent() {
            return !!(toInput.value.trim() || ccInput.value.trim() || bccInput.value.trim() || subject.value.trim() || editor.innerText.trim() || files.length);
        }

        function payload(extra) {
            const data = Object.assign({
                to: toInput.value, cc: ccInput.value, bcc: bccInput.value, subject: subject.value,
                body_html: (editor.innerText.trim() || editor.querySelector('img')) ? editor.innerHTML : '',
                body_plain: editor.innerText.replace(/ /g, ' ').replace(/\n{3,}/g, '\n\n').trim(),
            }, extra || {});
            if (draft.id) data.draft_id = draft.id;
            if (draft.replyTo) data.reply_to = draft.replyTo;
            const carriedIds = draft.carried ? draft.carried.list.map((a) => a.id) : [];
            if (draft.carried && carriedIds.length) {
                data.forward_of = draft.carried.source;
                data.forward_attachment_ids = carriedIds;
            }
            if (!files.length) return data;
            const fd = new FormData();
            for (const [k, v] of Object.entries(data)) {
                if (Array.isArray(v)) v.forEach((x) => fd.append(k + '[]', x));
                else fd.append(k, v);
            }
            for (const f of files) fd.append('attachments[]', f, f.name);
            return fd;
        }

        async function saveDraft(silent) {
            if (saving) return saving;
            if (!hasContent()) { if (!silent) toast('Nada para salvar ainda', 'error'); return null; }
            status.textContent = 'Salvando…';
            saving = (async () => {
                try {
                    const r = await api.post('/drafts', payload());
                    draft.id = r.message_id;
                    // Anexos agora estão no rascunho: passam a ser "carregados" dele.
                    try {
                        const m = await api.get('/messages/' + r.message_id);
                        draft.carried = { source: r.message_id, list: m.attachments.map((a) => ({ id: a.id, name: a.name, size: a.size })) };
                        files.length = 0;
                        renderAttachments();
                    } catch (_) { /* mantém lista local */ }
                    dirty = false;
                    status.textContent = 'Rascunho salvo às ' + new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
                    if (!silent) toast('Rascunho salvo', 'ok', 1800);
                    if (state.folder === 'DRAFTS') loadThreads(true, true);
                    loadFolders();
                    return r;
                } catch (e) {
                    status.textContent = 'Falha ao salvar';
                    if (!silent) toast(errorMessage(e), 'error');
                    throw e;
                } finally {
                    saving = null;
                }
            })();
            return saving;
        }

        async function send() {
            if (!toInput.value.trim() && !ccInput.value.trim() && !bccInput.value.trim()) { toast('Informe ao menos um destinatário', 'error'); toInput.focus(); return; }
            if (!subject.value.trim() && !(await confirm({ title: 'Sem assunto', message: 'Enviar a mensagem sem assunto?', confirmLabel: 'Enviar' }))) return;
            if (saving) await saving.catch(() => null);
            clearTimeout(autosaveTimer);
            setBusy(sendBtn, true, 'Enviando…');
            try {
                const r = await api.post('/send', payload());
                toast(r.copy_saved === false ? 'Mensagem enviada (cópia em Enviados não pôde ser salva)' : 'Mensagem enviada', 'ok');
                destroy(true);
                loadFolders();
                if (state.folder === 'SENT' || state.folder === 'DRAFTS') loadThreads(true, true);
                if (state.selected && r.thread_id === state.selected) {
                    const t = state.threads.find((x) => x.thread_id === state.selected);
                    if (t) openThread(t);
                }
            } catch (e) {
                toast(errorMessage(e) + (e.data && e.data.rejected ? ': ' + e.data.rejected.join('; ') : ''), 'error', 9000);
                setBusy(sendBtn, false);
            }
        }

        async function discard() {
            if (hasContent() && !(await confirm({ title: 'Descartar', danger: true, confirmLabel: 'Descartar', message: 'Descartar esta mensagem' + (draft.id ? ' e o rascunho salvo' : '') + '?' }))) return;
            if (draft.id) await api.del('/messages/' + draft.id).catch(() => null);
            destroy(true);
            loadFolders();
            if (state.folder === 'DRAFTS') loadThreads(true, true);
        }

        async function close() {
            if (dirty && hasContent()) {
                try { await saveDraft(true); toast('Rascunho salvo', 'ok', 1800); } catch (e) {
                    if (!(await confirm({ title: 'Não foi possível salvar', danger: true, confirmLabel: 'Fechar sem salvar', message: errorMessage(e) }))) return;
                }
            }
            destroy(true);
        }

        function destroy() {
            clearTimeout(autosaveTimer);
            root.remove();
            if (composer && composer.root === root) composer = null;
        }

        sendBtn.addEventListener('click', send);
        root.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); send(); }
            if (e.key === 'Escape' && !document.querySelector('.modal-backdrop')) { e.preventDefault(); close(); }
        });

        // ---------------------------------------------------------- sugestões de endereço
        for (const input of [toInput, ccInput, bccInput]) attachSuggestions(input);

        renderAttachments();
        setTimeout(() => (toInput.value ? (subject.value ? editor : subject) : toInput).focus(), 0);
        if (opts.html && toInput.value) {
            // posiciona o cursor no início (acima da citação)
            const range = document.createRange();
            range.setStart(editor, 0);
            range.collapse(true);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
        }

        return {
            root,
            dirty: () => dirty && hasContent(),
            saveDraft,
            destroy,
            focus: () => { root.classList.remove('minimized'); editor.focus(); },
        };
    }

    function attachSuggestions(input) {
        const box = h('ul.suggestions', { role: 'listbox', hidden: true });
        input.parentNode.appendChild(box);
        let items = [];
        let active = -1;
        let reqId = 0;

        const lastToken = () => {
            const parts = input.value.split(/[,;]/);
            return parts[parts.length - 1].trim();
        };
        const choose = (email) => {
            const parts = input.value.split(/[,;]/);
            parts[parts.length - 1] = ' ' + email;
            input.value = parts.join(',').replace(/^\s+/, '') + ', ';
            box.hidden = true;
            input.focus();
            input.dispatchEvent(new Event('input'));
        };
        const render = () => {
            clear(box);
            items.forEach((email, i) => box.appendChild(h('li', {
                role: 'option', 'aria-selected': i === active ? 'true' : 'false',
                onmousedown: (e) => { e.preventDefault(); choose(email); },
            }, email)));
            box.hidden = !items.length;
        };
        input.addEventListener('input', debounce(async () => {
            const q = lastToken();
            if (q.length < 2 || q.includes('@') && q.endsWith('.')) { items = []; render(); return; }
            const id = ++reqId;
            try {
                const r = await api.get('/contacts?q=' + encodeURIComponent(q.replace(/^.*</, '')));
                if (id !== reqId) return;
                items = r.contacts.filter((c) => !input.value.toLowerCase().includes(c + ',')).slice(0, 6);
                active = -1;
                render();
            } catch (_) { items = []; render(); }
        }, 200));
        input.addEventListener('keydown', (e) => {
            if (box.hidden) return;
            if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(items.length - 1, active + 1); render(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); render(); }
            else if ((e.key === 'Enter' || e.key === 'Tab') && active >= 0) { e.preventDefault(); choose(items[active]); }
            else if (e.key === 'Escape') { e.stopPropagation(); box.hidden = true; }
        });
        input.addEventListener('blur', () => setTimeout(() => { box.hidden = true; }, 150));
    }

    // =====================================================================
    // Conta
    // =====================================================================
    function changePasswordDialog() {
        const cur = h('input.input', { type: 'password', autocomplete: 'current-password', required: true });
        const nw = h('input.input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '10' });
        const nw2 = h('input.input', { type: 'password', autocomplete: 'new-password', required: true });
        modal({
            title: 'Alterar senha',
            body: h('form',
                h('p.stat-sub', 'Sua chave privada é re-cifrada com a nova senha; as mensagens continuam legíveis. Guarde bem a senha: ninguém consegue recuperá-la.'),
                field('Senha atual', cur), field('Nova senha', nw, 'Mínimo de 10 caracteres.'), field('Repita a nova senha', nw2)),
            actions: [{ label: 'Cancelar' }, {
                label: 'Alterar senha', kind: 'primary', onClick: async () => {
                    if (nw.value.length < 10) { toast('A nova senha precisa ter ao menos 10 caracteres', 'error'); return false; }
                    if (nw.value !== nw2.value) { toast('As senhas não conferem', 'error'); return false; }
                    await api.post('/password', { current_password: cur.value, new_password: nw.value });
                    toast('Senha alterada', 'ok');
                },
            }],
        });
    }

    // =====================================================================
    // Atalhos de teclado
    // =====================================================================
    document.addEventListener('keydown', (e) => {
        if (!state.me || e.ctrlKey || e.metaKey || e.altKey) return;
        const t = e.target;
        if (t.closest && (t.closest('input, textarea, select, [contenteditable="true"], .modal-backdrop, .composer'))) return;
        const m = state.thread && state.thread.messages[state.thread.messages.length - 1];
        switch (e.key) {
            case 'c': e.preventDefault(); openComposer({}); break;
            case '/': e.preventDefault(); ui.search.focus(); break;
            case 'j': e.preventDefault(); moveSelection(1); break;
            case 'k': e.preventDefault(); moveSelection(-1); break;
            case 'r': if (m) { e.preventDefault(); reply(m, false); } break;
            case 'a': if (m) { e.preventDefault(); reply(m, true); } break;
            case 'f': if (m) { e.preventDefault(); forward(m); } break;
            case 'e': if (state.selected && state.folder !== 'ARCHIVE') { e.preventDefault(); moveThread('ARCHIVE'); } break;
            case '#': case 'Delete': if (state.selected) { e.preventDefault(); deleteThread(); } break;
            case 's': if (state.selected) { e.preventDefault(); toggleStar(!state.thread.messages.some((x) => x.is_starred)); } break;
            case 'u': if (state.selected) { e.preventDefault(); markUnread(); } break;
            case 'Escape': if (state.selected) closeReader(); break;
            default: break;
        }
    });

    window.addEventListener('beforeunload', (e) => {
        if (composer && composer.dirty()) { e.preventDefault(); e.returnValue = ''; }
    });

    boot();
})();
