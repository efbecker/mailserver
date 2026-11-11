/* =============================================================================
 * Mail Platform :: Painel Admin
 * SPA sem dependências: login, visão geral, servidores (deploy SSH com logs
 * em tempo real via SSE), domínios (DKIM/DNS), contas, segurança (Fail2ban +
 * telemetria) e fila do Postfix.
 * ========================================================================== */
(function () {
    'use strict';

    const { h, clear, fill, $, toast, errorMessage, modal, confirm, bytes, dateTime, relative, copyText, formData, field, setBusy } = window.MP;
    const api = window.MP.createApi('/api/admin');
    const app = document.getElementById('app');

    const ROUTES = [
        { id: 'overview', label: 'Visão geral', ico: '◧' },
        { id: 'nodes', label: 'Servidores', ico: '⛁' },
        { id: 'domains', label: 'Domínios', ico: '◎' },
        { id: 'accounts', label: 'Contas', ico: '☺' },
        { id: 'security', label: 'Segurança', ico: '⛨' },
        { id: 'queue', label: 'Fila de envio', ico: '⇄' },
    ];
    const ROLE_LABEL = { db_timescale: 'Servidor 2 · Banco (TimescaleDB)', mail_frontend: 'Servidor 1 · Mail + Web' };
    const STATUS_BADGE = {
        pending: ['Pendente', ''], running: ['Em execução', 'accent'], deployed: ['Implantado', 'ok'],
        success: ['Implantado', 'ok'], failed: ['Falhou', 'danger'], error: ['Falhou', 'danger'],
    };

    let session = null;
    let main = null;
    let nav = null;
    let currentView = null;
    let viewToken = 0;

    api.state.onUnauthorized = () => {
        if (session) {
            session = null;
            toast('Sessão expirada. Entre novamente.', 'error');
            renderLogin();
        }
    };

    // =====================================================================
    // Inicialização e login
    // =====================================================================
    async function boot() {
        try {
            const s = await api.refreshCsrf();
            if (s.authenticated) {
                session = s;
                renderShell();
            } else {
                renderLogin();
            }
        } catch (e) {
            fill(app, h('div.auth-screen', h('div.auth-card',
                h('h2', 'Painel indisponível'),
                h('p', 'Não foi possível contatar o servidor. Verifique se seu IP está liberado (--admin-allow).'),
                h('button.btn.btn-primary', { onclick: boot }, 'Tentar novamente'))));
        }
    }

    function renderLogin() {
        document.title = 'Entrar · Painel Admin';
        const user = h('input.input', { name: 'username', autocomplete: 'username', required: true, value: 'admin' });
        const pass = h('input.input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
        const err = h('div.form-error', { role: 'alert' });
        const btn = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Entrar');
        const form = h('form', { novalidate: true },
            field('Usuário', user), field('Senha', pass), err, btn);
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            err.textContent = '';
            setBusy(btn, true, 'Verificando…');
            try {
                await api.refreshCsrf();
                const r = await api.post('/login', { username: user.value.trim(), password: pass.value }, { noAuthRedirect: true });
                pass.value = '';
                session = await api.refreshCsrf();
                session.user = session.user || r.user;
                renderShell();
            } catch (ex) {
                err.textContent = errorMessage(ex);
                pass.select();
            } finally {
                setBusy(btn, false);
            }
        });
        fill(app, h('div.auth-screen', h('div.auth-card',
            h('div.auth-brand', h('div.logo', 'MP'), h('div', h('h1', 'Painel Admin'), h('p.auth-sub', 'Mail Platform'))),
            form,
            h('p.auth-note', '🔒', 'Tentativas inválidas são registradas e bloqueadas pelo Fail2ban.'))));
        setTimeout(() => (user.value ? pass : user).focus(), 0);
    }

    async function logout() {
        try { await api.post('/logout'); } catch (_) { /* ignora */ }
        session = null;
        await api.refreshCsrf().catch(() => null);
        location.hash = '';
        renderLogin();
    }

    // =====================================================================
    // Shell e roteamento
    // =====================================================================
    function renderShell() {
        nav = h('nav.admin-nav', { 'aria-label': 'Navegação principal' },
            h('div.brand', h('div.logo', 'MP'), h('div', h('strong', 'Mail Platform'), h('small', session.hostname || 'Painel Admin'))),
            ROUTES.map((r) => h('a.nav-link', { href: '#' + r.id, dataset: { route: r.id } }, h('span.ico', { 'aria-hidden': 'true' }, r.ico), r.label)),
            h('div.spacer'),
            h('div.who', 'Conectado como ', h('strong', session.user || 'admin')),
            h('button.nav-link', { type: 'button', onclick: logout }, h('span.ico', '⏻'), 'Sair'));
        main = h('main.admin-main', { id: 'main', tabindex: '-1' });
        const topbar = h('div.admin-topbar',
            h('button.btn.btn-ghost.btn-icon', { type: 'button', 'aria-label': 'Menu', onclick: () => nav.classList.toggle('open') }, '☰'),
            h('strong', 'Painel Admin'));
        fill(app, h('div.admin-shell', nav, h('div', topbar, main)));
        nav.addEventListener('click', (e) => { if (e.target.closest('a')) nav.classList.remove('open'); });
        route();
    }

    window.addEventListener('hashchange', () => { if (session) route(); });

    function route() {
        const [view, arg] = (location.hash.replace(/^#/, '') || 'overview').split('/');
        const known = ROUTES.some((r) => r.id === view) ? view : 'overview';
        for (const a of nav.querySelectorAll('[data-route]')) {
            if (a.dataset.route === known) a.setAttribute('aria-current', 'page');
            else a.removeAttribute('aria-current');
        }
        if (currentView && currentView.destroy) currentView.destroy();
        currentView = null;
        const token = ++viewToken;
        fill(main, h('div.loading', h('span.spinner')));
        const views = { overview: viewOverview, nodes: viewNodes, domains: arg ? () => viewDomain(arg) : viewDomains, accounts: viewAccounts, security: viewSecurity, queue: viewQueue };
        document.title = (ROUTES.find((r) => r.id === known).label) + ' · Painel Admin';
        Promise.resolve(views[known]()).then((v) => {
            if (token !== viewToken) { if (v && v.destroy) v.destroy(); return; }
            currentView = v || null;
            fill(main, v && v.node ? v.node : v);
        }).catch((e) => {
            if (token !== viewToken) return;
            fill(main, h('div.card', h('h2', 'Não foi possível carregar'), h('p', errorMessage(e)),
                h('button.btn', { onclick: route }, 'Tentar novamente')));
        });
    }

    function pageHeader(title, subtitle, ...actions) {
        return h('div.page-header', h('div', h('h1', title), subtitle ? h('p', subtitle) : null), h('div.toolbar', actions));
    }

    function badge(text, kind) {
        return h('span.badge' + (kind ? '.badge-' + kind : ''), text);
    }

    function statusBadge(status) {
        const [label, kind] = STATUS_BADGE[status] || [status || '—', ''];
        return badge(label, kind);
    }

    function check(ok) {
        return ok ? h('span.check-ok', { title: 'Verificado' }, '✓') : h('span.check-fail', { title: 'Pendente' }, '✕');
    }

    function table(headers, rows, emptyText) {
        return h('div.table-wrap', h('table.table',
            h('thead', h('tr', headers.map((x) => (typeof x === 'string' ? h('th', x) : h('th', { class: x.cls }, x.label))))),
            h('tbody', rows.length ? rows : h('tr', h('td.empty', { colspan: headers.length }, emptyText || 'Nada por aqui ainda.')))));
    }

    function softError(e) {
        return h('div.notice.notice-danger', errorMessage(e));
    }

    // =====================================================================
    // Visão geral
    // =====================================================================
    async function viewOverview() {
        const [o, ev] = await Promise.all([api.get('/overview'), api.get('/security-events?hours=24&limit=8').catch(() => null)]);
        const stat = (label, value, sub) => h('div.stat', h('div.stat-label', label), h('div.stat-value', value), sub ? h('div.stat-sub', sub) : null);
        return h('div',
            pageHeader('Visão geral', (o.hostname || '') + (o.public_ip ? ' · ' + o.public_ip : ''),
                h('button.btn', { onclick: route }, '↻ Atualizar')),
            h('div.stats',
                stat('Domínios', o.domains),
                stat('Contas', o.accounts),
                stat('Servidores', o.nodes),
                stat('Armazenamento', bytes(o.storage_bytes), 'cifrado (Sealed Box)'),
                stat('Recebidas 24 h', o.received_24h, o.spam_24h + ' em spam'),
                stat('Enviadas 24 h', o.sent_24h),
                stat('Falhas de login 24 h', o.auth_fail_24h),
                stat('Banimentos 24 h', o.bans_24h)),
            ev ? h('div.card', h('div.card-header', h('h2', 'Eventos de segurança · últimas 24 h'), h('a.btn.btn-sm', { href: '#security' }, 'Ver tudo')),
                hourlyChart(ev.hourly || []), eventsTable(ev.events || [])) : null,
            (o.domains === 0) ? h('div.card', h('h2', 'Primeiros passos'),
                h('ol',
                    h('li', 'Cadastre seu domínio em ', h('a', { href: '#domains' }, 'Domínios'), ' e publique os registros DNS gerados.'),
                    h('li', 'Crie as contas de e-mail em ', h('a', { href: '#accounts' }, 'Contas'), '.'),
                    h('li', 'Acesse o ', h('a', { href: '/webmail.html' }, 'Webmail'), ' com a conta criada.'))) : null);
    }

    /** Barras empilhadas por hora (AUTH_FAIL, BAN, demais). */
    function hourlyChart(hourly) {
        const now = new Date();
        now.setMinutes(0, 0, 0);
        const buckets = [];
        for (let i = 23; i >= 0; i--) buckets.push({ t: new Date(now.getTime() - i * 3600e3), fail: 0, ban: 0, other: 0 });
        for (const r of hourly) {
            const t = window.MP.parseDate(r.bucket);
            if (!t) continue;
            const b = buckets.find((x) => Math.abs(x.t - t) < 1800e3);
            if (!b) continue;
            const n = Number(r.total) || 0;
            if (r.action === 'AUTH_FAIL') b.fail += n;
            else if (r.action === 'BAN') b.ban += n;
            else b.other += n;
        }
        const max = Math.max(1, ...buckets.map((b) => b.fail + b.ban + b.other));
        const seg = (cls, n) => {
            if (!n) return null;
            const s = h('div.seg.' + cls);
            s.style.height = (n / max * 100) + '%';
            return s;
        };
        const bars = h('div.bars', { role: 'img', 'aria-label': 'Eventos por hora nas últimas 24 horas' },
            buckets.map((b) => h('div.bar', { title: b.t.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) + ` · falhas ${b.fail} · bans ${b.ban} · outros ${b.other}` },
                seg('seg-fail', b.fail), seg('seg-ban', b.ban), seg('seg-other', b.other))));
        const fmt = (d) => d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
        return h('div',
            bars,
            h('div.bars-axis', h('span', fmt(buckets[0].t)), h('span', fmt(buckets[12].t)), h('span', 'agora')),
            h('div.legend', h('span', h('i.seg-fail'), 'Falhas de login'), h('span', h('i.seg-ban'), 'Banimentos'), h('span', h('i.seg-other'), 'Outros eventos')));
    }

    function eventsTable(events) {
        const kind = (a) => (a === 'BAN' || a.endsWith('FAIL') ? 'danger' : a === 'UNBAN' || a.endsWith('OK') ? 'ok' : '');
        return table(['Quando', 'Serviço', 'Ação', 'IP de origem', 'Detalhes'],
            events.map((e) => h('tr',
                h('td', { title: dateTime(e.event_time) }, relative(e.event_time)),
                h('td', e.service, e.jail_name ? h('div.stat-sub', e.jail_name) : null),
                h('td', badge(e.action, kind(e.action || ''))),
                h('td.mono', e.source_ip || '—'),
                h('td.wrap', e.details || ''))),
            'Nenhum evento no período.');
    }

    // =====================================================================
    // Servidores e deploy
    // =====================================================================
    async function viewNodes() {
        const { nodes } = await api.get('/nodes');
        const rows = nodes.map((n) => h('tr',
            h('td', h('strong', n.hostname), h('div.stat-sub', ROLE_LABEL[n.node_role] || n.node_role)),
            h('td.mono', n.ssh_user + '@' + n.ip_address + ':' + n.ssh_port),
            h('td', statusBadge(n.deploy_status), n.node_role === 'db_timescale' && n.has_db_credentials ? h('div.stat-sub', 'credenciais obtidas') : null),
            h('td', n.last_check ? relative(n.last_check) : '—'),
            h('td.actions', h('div.btn-group',
                h('button.btn.btn-sm', { onclick: () => testNode(n) }, 'Testar SSH'),
                h('button.btn.btn-sm.btn-primary', { onclick: () => deployDialog(n, nodes) }, 'Deploy'),
                h('button.btn.btn-sm', { onclick: () => showPublicKey(n) }, 'Chave'),
                h('button.btn.btn-sm.btn-ghost', { title: 'Mais ações', onclick: () => nodeMenu(n) }, '⋯')))));
        return h('div',
            pageHeader('Servidores', 'Nós gerenciados por SSH. A chave privada fica cifrada no banco (XChaCha20-Poly1305).',
                h('button.btn.btn-primary', { onclick: addNodeDialog }, '+ Adicionar servidor')),
            h('div.card', table(['Servidor', 'Acesso SSH', 'Status', 'Última checagem', ''], rows,
                'Nenhum servidor cadastrado. Adicione o Servidor 2 (banco) e depois o Servidor 1 (mail).')),
            h('div.card', h('h3', 'Ordem recomendada'),
                h('ol',
                    h('li', 'Cadastre o ', h('strong', 'Servidor 2'), ' e faça o deploy informando o IP do Servidor 1. O painel baixa as credenciais geradas.'),
                    h('li', 'Cadastre o ', h('strong', 'Servidor 1'), ' e faça o deploy apontando para o Servidor 2.'),
                    h('li', 'Adicione a chave pública exibida em “Chave” ao ', h('code', '~/.ssh/authorized_keys'), ' de cada servidor antes do primeiro teste.'))));
    }

    function addNodeDialog() {
        const role = h('select.select', { name: 'node_role' },
            h('option', { value: 'db_timescale' }, ROLE_LABEL.db_timescale),
            h('option', { value: 'mail_frontend' }, ROLE_LABEL.mail_frontend));
        const form = h('form',
            field('Função', role),
            h('div.form-row',
                field('Hostname', h('input.input', { name: 'hostname', required: true, placeholder: 'db.empresa.com.br' })),
                field('Endereço IP', h('input.input', { name: 'ip_address', required: true, placeholder: '203.0.113.20' }))),
            h('div.form-row',
                field('Usuário SSH', h('input.input', { name: 'ssh_user', value: 'root' })),
                field('Porta SSH', h('input.input', { name: 'ssh_port', type: 'number', value: '22', min: '1', max: '65535' }))),
            field('Chave privada SSH', h('textarea.textarea', { name: 'ssh_private_key', required: true, spellcheck: 'false', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' }),
                'Chaves OpenSSH sem senha (ed25519, ecdsa) ou PEM RSA/EC. Gere uma dedicada: ssh-keygen -t ed25519 -N "" -f mp_deploy'));
        modal({
            title: 'Adicionar servidor', body: form, wide: true,
            actions: [{ label: 'Cancelar' }, {
                label: 'Salvar', kind: 'primary', onClick: async () => {
                    const r = await api.post('/nodes', formData(form));
                    toast('Servidor cadastrado', 'ok');
                    route();
                    showPublicKey({ hostname: form.elements.hostname.value, public_key: r.public_key });
                },
            }],
        });
    }

    function showPublicKey(n) {
        if (!n.public_key) { toast('Não foi possível derivar a chave pública', 'error'); return; }
        modal({
            title: 'Chave pública · ' + n.hostname, wide: true,
            body: h('div',
                h('p', 'Adicione esta linha ao arquivo ', h('code', '~/.ssh/authorized_keys'), ' do usuário SSH no servidor:'),
                h('div.copy-field', h('code', n.public_key), h('button.btn.btn-sm', { onclick: () => copyText(n.public_key) }, 'Copiar'))),
            actions: [{ label: 'Fechar', kind: 'primary' }],
        });
    }

    async function testNode(n) {
        const t = toast('Testando conexão com ' + n.hostname + '…');
        try {
            const r = await api.post('/nodes/' + n.id + '/test');
            t.remove();
            modal({
                title: 'Teste SSH · ' + n.hostname,
                body: h('div',
                    h('p', r.ok ? badge('Conexão OK', 'ok') : badge('Comando falhou', 'danger')),
                    h('p', 'Impressão digital do host: ', h('code', r.host_key)),
                    r.first_use ? h('div.notice', 'Primeira conexão: a chave do host foi registrada (TOFU). Confira a impressão digital acima com ', h('code', 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'), '.') : null,
                    h('pre.terminal', r.output || '(sem saída)')),
                actions: [{ label: 'Fechar', kind: 'primary' }],
            });
            route();
        } catch (e) {
            t.remove();
            if (/chave do host|host key|fingerprint|impress/i.test(e.message || '')) {
                const ok = await confirm({
                    title: 'Chave do host mudou!', danger: true, confirmLabel: 'Esquecer chave antiga',
                    message: errorMessage(e) + ' Isso pode indicar reinstalação do servidor ou um ataque man-in-the-middle. Só continue se você reinstalou o servidor.',
                });
                if (ok) { await api.post('/nodes/' + n.id + '/forget-hostkey'); toast('Chave esquecida. Teste novamente.', 'ok'); }
            } else {
                toast(errorMessage(e), 'error');
            }
        }
    }

    function nodeMenu(n) {
        const m = modal({
            title: n.hostname,
            body: h('div.btn-group',
                h('button.btn', { onclick: async () => { m.close(); await api.post('/nodes/' + n.id + '/forget-hostkey'); toast('Chave do host esquecida', 'ok'); } }, 'Esquecer chave do host'),
                h('button.btn.btn-danger', {
                    onclick: async () => {
                        m.close();
                        if (await confirm({ title: 'Remover servidor', danger: true, confirmLabel: 'Remover', message: `Remover ${n.hostname} do painel? Nada é apagado no servidor; a chave SSH e as credenciais baixadas são descartadas.` })) {
                            try { await api.del('/nodes/' + n.id); toast('Servidor removido', 'ok'); route(); } catch (e) { toast(errorMessage(e), 'error'); }
                        }
                    },
                }, 'Remover servidor')),
            actions: [{ label: 'Fechar' }],
        });
    }

    function deployDialog(n, nodes) {
        let form;
        if (n.node_role === 'db_timescale') {
            form = h('form',
                h('p', 'Instala PostgreSQL 17 + TimescaleDB com TLS 1.3 obrigatório e libera a porta apenas para o Servidor 1.'),
                field('IP do Servidor 1 (visto pelo Servidor 2)', h('input.input', { name: 'allowed_ip', required: true, value: session.public_ip || '' })),
                field('Edição do TimescaleDB', h('select.select', { name: 'timescale_edition' },
                    h('option', { value: 'tsl' }, 'Community (TSL) · recomendado'),
                    h('option', { value: 'oss' }, 'Apache-2.0 (OSS)'))));
        } else {
            const dbs = nodes.filter((x) => x.node_role === 'db_timescale');
            form = h('form',
                h('p', 'Instala Apache, PHP-FPM, Postfix, OpenDKIM, Rspamd e Fail2ban e conecta ao banco do Servidor 2.'),
                field('Servidor de banco', h('select.select', { name: 'db_node_id' },
                    dbs.length ? dbs.map((d) => h('option', { value: d.id, disabled: !d.has_db_credentials }, d.hostname + (d.has_db_credentials ? '' : ' (faça o deploy primeiro)'))) : h('option', { value: '' }, 'Nenhum Servidor 2 cadastrado'))),
                h('div.form-row',
                    field('Hostname (FQDN)', h('input.input', { name: 'hostname', required: true, value: n.hostname })),
                    field('IP público', h('input.input', { name: 'public_ip', placeholder: 'opcional (atrás de NAT)' }))),
                h('div.form-row',
                    field('E-mail do Let’s Encrypt', h('input.input', { name: 'acme_email', type: 'email', placeholder: 'admin@empresa.com.br' })),
                    field('IPs liberados para o painel', h('input.input', { name: 'admin_allow', placeholder: '203.0.113.10, 198.51.100.0/24' }))));
        }
        modal({
            title: 'Deploy · ' + n.hostname, body: form,
            actions: [{ label: 'Cancelar' }, {
                label: 'Iniciar deploy', kind: 'primary', onClick: async () => {
                    const data = formData(form);
                    for (const k of Object.keys(data)) if (data[k] === '') delete data[k];
                    if (data.db_node_id) data.db_node_id = parseInt(data.db_node_id, 10);
                    const r = await api.post('/deploy', Object.assign({ node_id: n.id }, data));
                    openDeployStream(n, r.stream_url);
                },
            }],
        });
    }

    /** Terminal com o log do deploy em tempo real (EventSource / SSE). */
    function openDeployStream(n, url) {
        const term = h('div.terminal', { role: 'log', 'aria-live': 'polite' });
        const status = h('span', badge('Conectando…', 'accent'));
        let autoscroll = true;
        term.addEventListener('scroll', () => { autoscroll = term.scrollTop + term.clientHeight >= term.scrollHeight - 20; });
        const line = (text, ts, cls) => {
            const l = h('div' + (cls ? '.' + cls : ''), ts ? h('span.ln-time', ts) : null, text);
            term.appendChild(l);
            if (autoscroll) term.scrollTop = term.scrollHeight;
        };
        const es = new EventSource(url, { withCredentials: true });
        let finished = false;
        const m = modal({
            title: 'Deploy em andamento · ' + n.hostname, wide: true, locked: true,
            body: h('div', h('p', status, ' ', h('span.stat-sub', 'Não feche esta janela até o fim.')), term),
            actions: [
                { label: 'Copiar log', onClick: () => { copyText(term.innerText); return false; } },
                {
                    label: 'Fechar', onClick: () => {
                        if (!finished && !window.confirm('O deploy ainda está em execução no servidor. Fechar apenas para de acompanhar o log. Fechar mesmo assim?')) return false;
                        es.close();
                        route();
                        return true;
                    },
                },
            ],
        });
        es.addEventListener('status', (e) => {
            const d = JSON.parse(e.data);
            fill(status, badge(d.state === 'running' ? 'Em execução' : d.state, 'accent'));
        });
        es.addEventListener('log', (e) => {
            const d = JSON.parse(e.data);
            const t = d.line || '';
            const cls = /ERRO|ERROR|FALHA|falhou/i.test(t) ? 'ln-err' : /==>/.test(t) ? 'ln-step' : /\bOK\b|concluído/i.test(t) ? 'ln-ok' : '';
            line(t, d.ts, cls);
        });
        es.addEventListener('done', (e) => {
            const d = JSON.parse(e.data);
            finished = true;
            es.close();
            fill(status, d.ok ? badge('Concluído com sucesso', 'ok') : badge('Falhou (código ' + d.exit + ')', 'danger'));
            line(d.ok ? '✔ Deploy concluído.' : '✖ Deploy falhou. Revise o log acima.', null, d.ok ? 'ln-ok' : 'ln-err');
            toast(d.ok ? 'Deploy concluído em ' + n.hostname : 'Deploy falhou em ' + n.hostname, d.ok ? 'ok' : 'error');
        });
        es.onerror = () => {
            if (finished) return;
            if (es.readyState === EventSource.CLOSED) {
                finished = true;
                fill(status, badge('Conexão perdida', 'danger'));
                line('Conexão com o painel perdida. O deploy pode continuar no servidor; reexecute para conferir (é idempotente).', null, 'ln-err');
            }
        };
        return m;
    }

    // =====================================================================
    // Domínios
    // =====================================================================
    async function viewDomains() {
        const { domains } = await api.get('/domains');
        const rows = domains.map((d) => h('tr',
            h('td', h('a', { href: '#domains/' + d.id }, h('strong', d.domain_name)), d.active ? null : h('div', badge('inativo', 'warn'))),
            ['mx_verified', 'spf_verified', 'dkim_verified', 'dmarc_verified', 'ptr_verified'].map((k) => h('td', check(d[k]))),
            h('td.num', d.accounts),
            h('td.actions', h('a.btn.btn-sm', { href: '#domains/' + d.id }, 'Abrir'))));
        return h('div',
            pageHeader('Domínios', 'Cada domínio recebe uma chave DKIM RSA-2048 e os registros DNS recomendados.',
                h('button.btn.btn-primary', { onclick: addDomainDialog }, '+ Adicionar domínio')),
            h('div.card', table(['Domínio', 'MX', 'SPF', 'DKIM', 'DMARC', 'PTR', { label: 'Contas', cls: 'num' }, ''], rows, 'Nenhum domínio cadastrado.')));
    }

    function addDomainDialog() {
        const name = h('input.input', { name: 'domain_name', required: true, placeholder: 'empresa.com.br', autocapitalize: 'off', spellcheck: 'false' });
        const form = h('form',
            field('Domínio', name),
            h('div.form-row',
                field('Seletor DKIM', h('input.input', { name: 'dkim_selector', value: 'mail' }), 'Nome usado em <seletor>._domainkey'),
                field('Cota do domínio (MB)', h('input.input', { name: 'quota_mb', type: 'number', min: '1', placeholder: 'padrão' }))));
        modal({
            title: 'Adicionar domínio', body: form,
            actions: [{ label: 'Cancelar' }, {
                label: 'Criar e gerar DKIM', kind: 'primary', onClick: async () => {
                    const data = formData(form);
                    if (data.quota_mb === null) delete data.quota_mb;
                    const r = await api.post('/domains', data);
                    if (r.dkim_installed === false) toast('Domínio criado, mas o OpenDKIM não foi atualizado: ' + (r.dkim_message || ''), 'error', 9000);
                    else toast('Domínio criado. Publique os registros DNS.', 'ok');
                    location.hash = '#domains/' + r.id;
                },
            }],
        });
    }

    async function viewDomain(id) {
        const { domain: d, records } = await api.get('/domains/' + encodeURIComponent(id));
        const results = h('div');
        const verifyBtn = h('button.btn.btn-primary', { onclick: () => verify() }, 'Verificar DNS agora');

        async function verify() {
            setBusy(verifyBtn, true, 'Consultando DNS…');
            try {
                const r = await api.post('/domains/' + d.id + '/verify');
                renderResults(r);
            } catch (e) {
                toast(errorMessage(e), 'error');
            } finally {
                setBusy(verifyBtn, false);
            }
        }

        function renderResults(r) {
            const labels = { mx: 'MX', spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', ptr: 'PTR (rDNS)' };
            fill(results, h('div.card',
                h('div.card-header', h('h3', 'Resultado da verificação'), h('span.stat-sub', 'em ' + dateTime(r.checked_at))),
                table(['Registro', 'Situação', 'Encontrado no DNS'],
                    Object.keys(labels).map((k) => {
                        const x = r.results[k] || { ok: false, found: [] };
                        return h('tr', h('td', h('strong', labels[k])),
                            h('td', x.ok ? badge('OK', 'ok') : badge(x.found.length ? 'Divergente' : 'Não encontrado', x.found.length ? 'warn' : 'danger')),
                            h('td.wrap.mono', x.found.length ? x.found.join('\n') : '—'));
                    }))));
        }

        const recordRows = records.map((r) => h('tr',
            h('td', badge(r.type, 'accent')),
            h('td.col-name', h('div.copy-field', h('code', r.name), h('button.btn.btn-sm', { onclick: () => copyText(r.name), title: 'Copiar nome' }, '⧉'))),
            h('td', h('div.copy-field', h('code', (r.priority !== null && r.priority !== undefined ? r.priority + ' ' : '') + r.value),
                h('button.btn.btn-sm', { onclick: () => copyText(r.value), title: 'Copiar valor' }, '⧉')),
            h('div.dns-found', r.note))));

        const activeToggle = h('button.btn', {
            onclick: async () => {
                try { await api.patch('/domains/' + d.id, { active: !d.active }); toast(d.active ? 'Domínio desativado' : 'Domínio ativado', 'ok'); route(); } catch (e) { toast(errorMessage(e), 'error'); }
            },
        }, d.active ? 'Desativar' : 'Ativar');

        return h('div',
            pageHeader(d.domain_name, 'Seletor DKIM: ' + d.dkim_selector + ' · criado em ' + dateTime(d.created_at),
                h('a.btn', { href: '#domains' }, '← Domínios'),
                h('a.btn', { href: '#accounts?domain=' + d.id, onclick: (e) => { e.preventDefault(); accountsFilter = d.id; location.hash = '#accounts'; } }, 'Contas'),
                verifyBtn),
            h('div.stats',
                ['mx', 'spf', 'dkim', 'dmarc', 'ptr'].map((k) => h('div.stat', h('div.stat-label', k.toUpperCase()), h('div.stat-value', check(d[k + '_verified'])))),
                h('div.stat', h('div.stat-label', 'Status'), h('div.stat-value', d.active ? badge('Ativo', 'ok') : badge('Inativo', 'warn')))),
            results,
            h('div.card',
                h('div.card-header', h('h2', 'Registros DNS para publicar'), h('span.stat-sub', 'Cloudflare: registros de e-mail sempre “DNS only” (nuvem cinza).')),
                table(['Tipo', 'Nome', 'Valor'], recordRows)),
            h('div.card',
                h('h3', 'Manutenção'),
                h('div.btn-group',
                    h('button.btn', {
                        onclick: async (e) => {
                            setBusy(e.currentTarget, true, 'Instalando…');
                            const b = e.currentTarget;
                            try { const r = await api.post('/domains/' + d.id + '/dkim/install'); toast(r.message || 'Chave DKIM instalada', 'ok'); } catch (ex) { toast(errorMessage(ex), 'error'); } finally { setBusy(b, false); }
                        },
                    }, 'Reinstalar chave no OpenDKIM'),
                    activeToggle,
                    h('button.btn.btn-danger', {
                        onclick: async () => {
                            const typed = await confirm({
                                title: 'Excluir domínio', danger: true, confirmLabel: 'Excluir definitivamente', typeToConfirm: d.domain_name,
                                message: 'Isto apaga o domínio, TODAS as contas e TODAS as mensagens dele. Não há como desfazer.',
                            });
                            if (!typed) return;
                            try { await api.del('/domains/' + d.id, { confirm: typed }); toast('Domínio excluído', 'ok'); location.hash = '#domains'; } catch (e) { toast(errorMessage(e), 'error'); }
                        },
                    }, 'Excluir domínio'))));
    }

    // =====================================================================
    // Contas
    // =====================================================================
    let accountsFilter = 0;

    async function viewAccounts() {
        const [{ domains }, { accounts }] = await Promise.all([api.get('/domains'), api.get('/accounts' + (accountsFilter ? '?domain_id=' + accountsFilter : ''))]);
        const filter = h('select.select', {
            'aria-label': 'Filtrar por domínio',
            onchange: (e) => { accountsFilter = parseInt(e.target.value, 10) || 0; route(); },
        }, h('option', { value: '0' }, 'Todos os domínios'), domains.map((d) => h('option', { value: d.id, selected: d.id === accountsFilter }, d.domain_name)));
        const rows = accounts.map((a) => {
            const pct = a.quota_bytes ? Math.min(100, a.used_bytes / a.quota_bytes * 100) : 0;
            const meter = h('div.meter' + (pct > 90 ? '.danger' : pct > 75 ? '.warn' : ''), h('span'));
            meter.firstChild.style.width = pct.toFixed(1) + '%';
            return h('tr',
                h('td', h('strong', a.email), h('div.stat-sub', a.full_name)),
                h('td', a.active ? badge('Ativa', 'ok') : badge('Inativa', 'warn')),
                h('td', meter, h('div.stat-sub', bytes(a.used_bytes) + ' de ' + bytes(a.quota_bytes))),
                h('td', dateTime(a.created_at)),
                h('td.actions', h('div.btn-group',
                    h('button.btn.btn-sm', { onclick: () => editAccountDialog(a) }, 'Editar'),
                    h('button.btn.btn-sm', { onclick: () => resetPasswordDialog(a) }, 'Redefinir senha'),
                    h('button.btn.btn-sm.btn-ghost', { title: 'Excluir', 'aria-label': 'Excluir ' + a.email, onclick: () => deleteAccount(a) }, '🗑'))));
        });
        return h('div',
            pageHeader('Contas', 'Cada conta tem seu par de chaves X25519; a chave privada só é aberta com a senha do usuário.',
                filter,
                h('button.btn.btn-primary', { disabled: !domains.length, onclick: () => addAccountDialog(domains) }, '+ Nova conta')),
            domains.length ? null : h('div.notice', 'Cadastre um domínio antes de criar contas.'),
            h('div.card', table(['Conta', 'Status', 'Uso da cota', 'Criada em', ''], rows, 'Nenhuma conta encontrada.')));
    }

    function generatePassword() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_.';
        const buf = new Uint32Array(18);
        crypto.getRandomValues(buf);
        return Array.from(buf, (n) => chars[n % chars.length]).join('');
    }

    function passwordField(name, label) {
        const input = h('input.input', { name, type: 'text', required: true, minlength: '10', autocomplete: 'new-password', spellcheck: 'false' });
        const gen = h('button.btn', { type: 'button', onclick: () => { input.value = generatePassword(); input.select(); } }, 'Gerar');
        const copy = h('button.btn', { type: 'button', onclick: () => input.value && copyText(input.value) }, 'Copiar');
        input.id = 'f_' + name;
        return h('div.field', h('label', { for: input.id }, label), h('div.copy-field', input, gen, copy),
            h('span.hint', 'Mínimo de 10 caracteres. Sem a senha, as mensagens da conta não podem ser lidas por ninguém (nem pelo admin).'));
    }

    function addAccountDialog(domains) {
        const local = h('input.input', { name: 'local', required: true, placeholder: 'joao.silva', autocapitalize: 'off', spellcheck: 'false' });
        const domain = h('select.select', { name: 'domain' }, domains.map((d) => h('option', { value: d.domain_name, selected: d.id === accountsFilter }, '@' + d.domain_name)));
        const form = h('form',
            h('div.field', h('label', { for: 'f_local' }, 'Endereço'), h('div.copy-field', Object.assign(local, { id: 'f_local' }), domain)),
            field('Nome completo', h('input.input', { name: 'full_name', required: true })),
            passwordField('password', 'Senha inicial'),
            field('Cota (MB)', h('input.input', { name: 'quota_mb', type: 'number', min: '1', value: '5120' })));
        modal({
            title: 'Nova conta', body: form,
            actions: [{ label: 'Cancelar' }, {
                label: 'Criar conta', kind: 'primary', onClick: async () => {
                    const d = formData(form);
                    const r = await api.post('/accounts', { email: d.local.toLowerCase() + '@' + d.domain, full_name: d.full_name, password: d.password, quota_mb: d.quota_mb || 5120 });
                    toast('Conta ' + r.email + ' criada', 'ok');
                    route();
                },
            }],
        });
    }

    function editAccountDialog(a) {
        const form = h('form',
            field('Nome completo', h('input.input', { name: 'full_name', value: a.full_name })),
            field('Cota (MB)', h('input.input', { name: 'quota_mb', type: 'number', min: '1', value: String(Math.round(a.quota_bytes / 1048576)) })),
            h('label.checkbox', h('input', { type: 'checkbox', name: 'active', checked: a.active }), h('span', 'Conta ativa (desmarque para bloquear login e recebimento)')));
        modal({
            title: 'Editar ' + a.email, body: form,
            actions: [{ label: 'Cancelar' }, {
                label: 'Salvar', kind: 'primary', onClick: async () => {
                    await api.patch('/accounts/' + a.id, formData(form));
                    toast('Conta atualizada', 'ok');
                    route();
                },
            }],
        });
    }

    function resetPasswordDialog(a) {
        const form = h('form',
            h('div.notice.notice-danger', 'Criptografia zero-knowledge: sem a senha atual a chave privada não pode ser recuperada. Um NOVO par de chaves será gerado e as mensagens existentes ficarão ilegíveis.'),
            h('p'),
            h('p', 'Para o próprio usuário trocar a senha mantendo as mensagens, use “Alterar senha” no Webmail.'),
            passwordField('password', 'Nova senha'),
            h('label.checkbox', h('input', { type: 'checkbox', name: 'confirm_data_loss' }), h('span', 'Entendo que as mensagens atuais ficarão ilegíveis')),
            h('label.checkbox', h('input', { type: 'checkbox', name: 'purge_messages', checked: true }), h('span', 'Apagar as mensagens ilegíveis e liberar a cota')));
        modal({
            title: 'Redefinir senha · ' + a.email, body: form,
            actions: [{ label: 'Cancelar' }, {
                label: 'Redefinir', kind: 'danger', onClick: async () => {
                    const d = formData(form);
                    if (!d.confirm_data_loss) { toast('Marque a confirmação de perda de dados', 'error'); return false; }
                    const r = await api.post('/accounts/' + a.id + '/reset-password', d);
                    toast('Senha redefinida' + (r.purged ? ' · ' + r.purged + ' mensagens apagadas' : ''), 'ok');
                    route();
                },
            }],
        });
    }

    async function deleteAccount(a) {
        const typed = await confirm({
            title: 'Excluir conta', danger: true, confirmLabel: 'Excluir definitivamente', typeToConfirm: a.email,
            message: 'A conta e todas as suas mensagens serão apagadas. Não há como desfazer.',
        });
        if (!typed) return;
        try { await api.del('/accounts/' + a.id, { confirm: typed }); toast('Conta excluída', 'ok'); route(); } catch (e) { toast(errorMessage(e), 'error'); }
    }

    // =====================================================================
    // Segurança: Fail2ban + telemetria
    // =====================================================================
    async function viewSecurity() {
        const hoursSel = h('select.select', { 'aria-label': 'Período' },
            [[24, 'Últimas 24 h'], [168, 'Últimos 7 dias'], [720, 'Últimos 30 dias']].map(([v, l]) => h('option', { value: v }, l)));
        const serviceSel = h('select.select', { 'aria-label': 'Serviço' },
            h('option', { value: '' }, 'Todos os serviços'),
            ['fail2ban', 'webmail', 'admin_auth', 'webmail_auth', 'ssh_deploy'].map((s) => h('option', { value: s }, s)));
        const eventsBox = h('div', h('div.loading', h('span.spinner')));
        const chartBox = h('div');
        const f2bBox = h('div', h('div.loading', h('span.spinner')));

        async function loadEvents() {
            try {
                const q = '?limit=300&hours=' + hoursSel.value + (serviceSel.value ? '&service=' + encodeURIComponent(serviceSel.value) : '');
                const r = await api.get('/security-events' + q);
                fill(chartBox, hourlyChart(r.hourly || []));
                fill(eventsBox, eventsTable(r.events || []));
            } catch (e) { fill(eventsBox, softError(e)); }
        }

        async function loadF2b() {
            try {
                const r = await api.get('/fail2ban');
                fill(f2bBox, 
                    h('p.stat-sub', r.total_banned + ' IP(s) banido(s) no momento'),
                    table(['Jail', 'IPs banidos'], r.jails.map((j) => h('tr',
                        h('td', h('strong', j.name)),
                        h('td', j.banned.length ? h('div.ip-list', j.banned.map((ip) => h('span.ip-chip', ip,
                            h('button.btn.btn-ghost.btn-icon.btn-sm', { title: 'Desbanir ' + ip, 'aria-label': 'Desbanir ' + ip, onclick: () => unban(j.name, ip) }, '✕')))) : h('span.stat-sub', 'nenhum'))))));
            } catch (e) { fill(f2bBox, softError(e)); }
        }

        async function unban(jail, ip) {
            if (!(await confirm({ title: 'Desbanir IP', message: `Remover ${ip} da jail ${jail}?`, confirmLabel: 'Desbanir' }))) return;
            try { await api.post('/fail2ban/unban', { jail, ip }); toast(ip + ' desbanido', 'ok'); loadF2b(); loadEvents(); } catch (e) { toast(errorMessage(e), 'error'); }
        }

        const banIp = h('input.input', { placeholder: 'IP a banir', 'aria-label': 'IP' });
        const banJail = h('select.select', { 'aria-label': 'Jail' }, ['recidive', 'sshd', 'postfix', 'postfix-sasl', 'apache-auth', 'mail-platform-auth'].map((j) => h('option', { value: j }, j)));
        const banForm = h('form.toolbar', banIp, banJail, h('button.btn.btn-danger', { type: 'submit' }, 'Banir'));
        banForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            try { await api.post('/fail2ban/ban', { jail: banJail.value, ip: banIp.value.trim() }); toast(banIp.value + ' banido', 'ok'); banIp.value = ''; loadF2b(); } catch (ex) { toast(errorMessage(ex), 'error'); }
        });
        hoursSel.addEventListener('change', loadEvents);
        serviceSel.addEventListener('change', loadEvents);
        loadEvents();
        loadF2b();

        return h('div',
            pageHeader('Segurança', 'Fail2ban e eventos registrados no TimescaleDB.', h('button.btn', { onclick: () => { loadEvents(); loadF2b(); } }, '↻ Atualizar')),
            h('div.card', h('div.card-header', h('h2', 'Fail2ban'), banForm), f2bBox),
            h('div.card', h('div.card-header', h('h2', 'Eventos de segurança'), h('div.toolbar', serviceSel, hoursSel)),
                h('p.stat-sub', 'Distribuição por hora (últimas 24 h)'), chartBox, h('p'), eventsBox));
    }

    // =====================================================================
    // Fila do Postfix
    // =====================================================================
    async function viewQueue() {
        let data;
        let err = null;
        try { data = await api.get('/queue'); } catch (e) { err = e; data = { queue: [], count: 0 }; }
        const rows = data.queue.map((q) => h('tr',
            h('td.mono', q.queue_id),
            h('td', badge(q.queue_name, q.queue_name === 'deferred' ? 'warn' : q.queue_name === 'hold' ? 'danger' : '')),
            h('td', dateTime(q.arrival_time)),
            h('td.wrap', q.sender || '<>'),
            h('td', q.recipients.map((r) => h('div', h('span.wrap', r.address), r.reason ? h('div.dns-found', r.reason) : null))),
            h('td.num', bytes(q.size))));
        return h('div',
            pageHeader('Fila de envio', data.count + ' mensagem(ns) na fila do Postfix',
                h('button.btn', { onclick: route }, '↻ Atualizar'),
                h('button.btn.btn-primary', {
                    onclick: async (e) => {
                        const b = e.currentTarget;
                        setBusy(b, true, 'Reenviando…');
                        try { await api.post('/queue/flush'); toast('Reenvio solicitado', 'ok'); setTimeout(route, 1500); } catch (ex) { toast(errorMessage(ex), 'error'); } finally { setBusy(b, false); }
                    },
                }, 'Reenviar agora (flush)')),
            err ? softError(err) : null,
            h('div.card', table(['ID', 'Fila', 'Chegada', 'Remetente', 'Destinatários', { label: 'Tamanho', cls: 'num' }], rows, 'Fila vazia. Tudo entregue.')));
    }

    boot();
})();
