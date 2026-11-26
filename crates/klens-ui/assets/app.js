(() => {
  'use strict';

  const state = {
    status: null,
    activeTab: 'blueprint',
    memorySubtab: 'vault',
    i18nEn: {},
    i18nCur: {},
    lang: 'en',
    bpSnapshotKey: '',
    bpPollTimer: null,
    graphData: null,
    selectedNodePath: null,
    collapsedClusters: new Set(),
    memFilter: 'all',
    memSearch: '',
    memDir: '',
    selectedNoteId: null,
    runsList: [],
    selectedRunId: null,
    runRawMode: false,
    statsRange: '7d',
    statsScope: 'all',
    pickerPath: null,
    pickerReadOnly: false,
    isShutDown: false,
  };

  const $ = (id) => document.getElementById(id);

  function escHtml(v) {
    return String(v ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fmtNum(n) {
    return Number(n || 0).toLocaleString();
  }

  function t(key) {
    return state.i18nCur[key] || state.i18nEn[key] || key;
  }

  function applyI18nDom() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });
  }

  async function loadI18n(lang) {
    if (!Object.keys(state.i18nEn).length) {
      const r = await fetch('/i18n/en.json', { credentials: 'same-origin' });
      if (r.ok) state.i18nEn = await r.json();
    }
    state.lang = lang || 'en';
    if (state.lang === 'en') {
      state.i18nCur = state.i18nEn;
    } else {
      const r = await fetch(`/i18n/${encodeURIComponent(state.lang)}.json`, {
        credentials: 'same-origin',
      });
      state.i18nCur = r.ok ? await r.json() : {};
    }
    const sel = $('select-lang');
    if (sel) sel.value = state.lang;
    applyI18nDom();
  }

  function toast(msg, kind = 'info') {
    const host = $('toast-container');
    if (!host) return;
    const node = document.createElement('div');
    node.className = `toast ${kind}`;
    node.textContent = msg;
    host.appendChild(node);
    setTimeout(() => node.remove(), 3400);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast(t('toast.copied'), 'ok');
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      toast(t('toast.copied'), 'ok');
    }
  }

  function showAuthRequired() {
    $('view-auth').classList.remove('hidden');
    $('view-welcome').classList.add('hidden');
    $('tab-bar').classList.add('hidden');
    document.querySelectorAll('.tab-pane').forEach((p) => p.classList.add('hidden'));
  }

  async function api(url, opts = {}) {
    if (state.isShutDown) return Promise.reject(new Error(t('shutdown.title')));
    const headers = Object.assign({ 'X-Klens-Request': '1' }, opts.headers || {});
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(url, {
      method: opts.method || 'GET',
      credentials: 'same-origin',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { message: text };
    }
    if (res.status === 401) {
      showAuthRequired();
      throw new Error(data.message || 'Unauthorized');
    }
    if (!res.ok) {
      throw new Error(data.message || `HTTP ${res.status}`);
    }
    return data;
  }

  function openModal(title, html, onBind) {
    $('modal-title').textContent = title;
    const body = $('modal-body');
    body.innerHTML = html;
    $('modal-backdrop').classList.remove('hidden');
    if (onBind) onBind(body);
  }

  function closeModal() {
    $('modal-backdrop').classList.add('hidden');
    $('modal-body').innerHTML = '';
  }

  function enterShutdownState() {
    state.isShutDown = true;
    if (state.bpPollTimer) {
      clearInterval(state.bpPollTimer);
      state.bpPollTimer = null;
    }
    closeModal();
    document
      .querySelectorAll('.topbar, .tab-bar, .main-shell')
      .forEach((root) => root.querySelectorAll('button, input, select, textarea').forEach((el) => { el.disabled = true; }));
    $('shutdown-overlay')?.classList.remove('hidden');
    document.title = `${t('app.name')} — ${t('shutdown.title')}`;
  }

  function initTheme() {
    const saved = localStorage.getItem('klens_theme');
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.setAttribute('data-theme', saved);
    }
    $('btn-theme').addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme');
      const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      const effectiveLight = cur ? cur === 'light' : prefersLight;
      const next = effectiveLight ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('klens_theme', next);
    });
  }

  function setHealthDot(light) {
    const dot = $('health-dot');
    dot.className = 'traffic-dot';
    if (light === 'GREEN') dot.classList.add('dot-green');
    else if (light === 'YELLOW') dot.classList.add('dot-yellow');
    else if (light === 'RED') dot.classList.add('dot-red');
    else dot.classList.add('dot-neutral');
  }

  async function refreshHealthLight() {
    try {
      const env = await api('/api/code/health');
      setHealthDot(env.data && env.data.overall);
    } catch {
      setHealthDot('neutral');
    }
  }

  function renderWelcome(registered) {
    const list = $('welcome-registered-list');
    if (!registered.length) {
      list.innerHTML = `<p class="muted">${escHtml(t('welcome.noRegistered'))}</p>`;
      return;
    }
    list.innerHTML = registered
      .map(
        (p) => `
      <div class="list-item" data-open-path="${escHtml(p.path)}">
        <div>
          <strong>${escHtml(p.name)}</strong>
          <div class="muted small mono">${escHtml(p.path)}</div>
        </div>
        <span class="badge">${escHtml(p.mode || 'active')}</span>
      </div>`
      )
      .join('');
    list.querySelectorAll('[data-open-path]').forEach((el) => {
      el.addEventListener('click', () =>
        selectProject(el.dataset.openPath, !!state.status?.cli_read_only_locked)
      );
    });
  }

  async function selectProject(path, readOnly) {
    try {
      const payload = { path };
      if (readOnly !== null && readOnly !== undefined) payload.read_only = !!readOnly;
      await api('/api/projects/select', { method: 'POST', body: payload });
      state.bpSnapshotKey = '';
      state.selectedNodePath = null;
      state.selectedNoteId = null;
      state.selectedRunId = null;
      closeModal();
      await refreshStatus();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function switchTab(tab, forceLoad = false) {
    state.activeTab = tab;
    document.querySelectorAll('.tab-btn').forEach((btn) => {
      const active = btn.dataset.tab === tab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    document.querySelectorAll('.tab-pane').forEach((pane) => {
      pane.classList.toggle('hidden', pane.id !== `tab-${tab}`);
    });

    if (state.bpPollTimer) {
      clearInterval(state.bpPollTimer);
      state.bpPollTimer = null;
    }

    const views = window.KlensViews || {};
    if (tab === 'blueprint' && views.loadBlueprint) {
      views.loadBlueprint(forceLoad);
      state.bpPollTimer = setInterval(() => {
        if (!state.isShutDown && state.activeTab === 'blueprint' && state.status?.active_project) {
          views.loadBlueprint(false);
        }
      }, 2000);
    } else if (tab === 'code' && views.loadCodeGraph) {
      views.loadCodeGraph();
    } else if (tab === 'memory') {
      if (state.memorySubtab === 'vault' && views.loadMemoryList) views.loadMemoryList();
      else if (views.loadRunsList) views.loadRunsList();
    } else if (tab === 'stats' && views.loadStats) {
      views.loadStats();
    }
  }

  async function refreshStatus() {
    const st = await api('/api/status');
    state.status = st;
    await loadI18n(st.ui_lang || 'en');

    const proj = st.active_project;
    $('active-project-label').textContent = proj ? proj.name : t('topbar.selectProject');
    $('btn-project-picker').title = proj ? proj.path : t('topbar.selectProject');
    $('badge-readonly').classList.toggle('hidden', !st.read_only);
    state.pickerReadOnly = !!st.cli_read_only_locked;

    $('view-auth').classList.add('hidden');
    if (!proj) {
      $('tab-bar').classList.add('hidden');
      document.querySelectorAll('.tab-pane').forEach((p) => p.classList.add('hidden'));
      renderWelcome(st.registered_projects || []);
      $('view-welcome').classList.remove('hidden');
      setHealthDot('neutral');
      return;
    }

    $('view-welcome').classList.add('hidden');
    $('tab-bar').classList.remove('hidden');
    switchTab(state.activeTab, true);
    refreshHealthLight();
  }

  const normPath = (p) => String(p || '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();

  async function renderFolderPicker(dirPath) {
    const q = dirPath ? `?path=${encodeURIComponent(dirPath)}` : '';
    let data;
    try {
      data = await api(`/api/fs/dirs${q}`);
    } catch (err) {
      return toast(err.message, 'error');
    }
    state.pickerPath = data.current;
    const cliLocked = !!state.status?.cli_read_only_locked;
    const roChecked = cliLocked || state.pickerReadOnly;
    const registered = state.status?.registered_projects || [];
    const activeNorm = normPath(state.status?.active_project?.path);

    const regHtml = registered.length
      ? registered
          .map((p) => {
            const isAct = activeNorm && normPath(p.path) === activeNorm;
            return `<div class="list-item${isAct ? ' active' : ''}" data-reg-path="${escHtml(p.path)}">
              <div><strong>${escHtml(p.name)}</strong><div class="muted small mono">${escHtml(p.path)}</div></div>
              <div class="row gap-sm">
                ${isAct ? '<span class="badge badge-green">active</span>' : ''}
                <span class="badge">${escHtml(p.mode || 'active')}</span>
              </div>
            </div>`;
          })
          .join('')
      : `<p class="muted small">${escHtml(t('welcome.noRegistered'))}</p>`;

    const shortcutsHtml = (data.shortcuts || [])
      .map((s) => `<button class="pill" data-jump="${escHtml(s.path)}" type="button">${escHtml(s.label)}</button>`)
      .join('');
    const dirsHtml = (data.dirs || [])
      .map(
        (d) => `<div class="list-item" data-dir="${escHtml(d.path)}">
        <span class="mono small">${escHtml(d.name)}</span>
        <div class="row gap-sm">
          ${d.has_project_markers ? '<span class="badge badge-blue">project</span>' : ''}
          <button class="btn btn-ghost small" data-open-dir="${escHtml(d.path)}" type="button">Open</button>
        </div>
      </div>`
      )
      .join('');

    openModal(
      t('modal.folderTitle'),
      `<div class="picker-section">
        <div class="small muted" style="font-weight:600;margin-bottom:6px">${escHtml(t('modal.registeredProjects'))}</div>
        <div class="list-stack" style="max-height:180px;overflow:auto">${regHtml}</div>
      </div>
      <hr class="modal-divider" />
      <div class="small muted" style="font-weight:600">${escHtml(t('modal.browseFolders'))}</div>
      <div class="row gap-sm">
        <button class="pill" data-jump="" type="button">${escHtml(t('modal.roots'))}</button>
        ${shortcutsHtml}
      </div>
      <div class="row gap-sm">
        <button id="btn-picker-up" class="btn btn-ghost small" type="button" ${data.current ? '' : 'disabled'}>${escHtml(t('modal.parentDir'))}</button>
        <span class="mono small muted" style="flex:1;word-break:break-all">${escHtml(data.current || t('modal.roots'))}</span>
        ${data.current ? `<button id="btn-picker-scan" class="btn btn-ghost small" type="button">${escHtml(t('modal.scanHere'))}</button>` : ''}
        ${data.current ? `<button id="btn-picker-open" class="btn btn-primary small" type="button">${escHtml(t('modal.openHere'))}</button>` : ''}
      </div>
      <label class="row gap-sm small muted">
        <input id="chk-picker-ro" type="checkbox" ${roChecked ? 'checked' : ''} ${cliLocked ? 'disabled' : ''} />
        ${escHtml(t('modal.openReadOnly'))}
      </label>
      <div id="picker-scan-results"></div>
      <div class="list-stack" style="max-height:260px;overflow:auto">${dirsHtml || '<p class="muted small">Empty directory</p>'}</div>`,
      (body) => {
        const roChk = body.querySelector('#chk-picker-ro');
        roChk.addEventListener('change', () => { state.pickerReadOnly = roChk.checked; });
        body.querySelectorAll('[data-reg-path]').forEach((el) =>
          el.addEventListener('click', () => selectProject(el.dataset.regPath, roChk.checked))
        );
        body.querySelectorAll('[data-jump]').forEach((btn) =>
          btn.addEventListener('click', () => renderFolderPicker(btn.dataset.jump || null))
        );
        body.querySelectorAll('[data-dir]').forEach((el) =>
          el.addEventListener('click', (ev) => {
            if (!ev.target.closest('[data-open-dir]')) renderFolderPicker(el.dataset.dir);
          })
        );
        body.querySelectorAll('[data-open-dir]').forEach((btn) =>
          btn.addEventListener('click', () => selectProject(btn.dataset.openDir, roChk.checked))
        );
        body.querySelector('#btn-picker-up')?.addEventListener('click', () => renderFolderPicker(data.parent || null));
        body.querySelector('#btn-picker-open')?.addEventListener('click', () => selectProject(data.current, roChk.checked));
        body.querySelector('#btn-picker-scan')?.addEventListener('click', async () => {
          try {
            const rep = await api('/api/projects/scan', { method: 'POST', body: { path: data.current, depth: 2 } });
            const out = body.querySelector('#picker-scan-results');
            out.innerHTML = `<div class="card"><div class="small muted">Found ${(rep.projects || []).length} project(s)</div><div class="list-stack mt-sm">${(rep.projects || [])
              .map((p) => `<div class="list-item" data-scanned="${escHtml(p.path)}"><strong>${escHtml(p.name)}</strong><span class="mono small muted">${escHtml(p.path)}</span></div>`)
              .join('')}</div></div>`;
            out.querySelectorAll('[data-scanned]').forEach((el) =>
              el.addEventListener('click', () => selectProject(el.dataset.scanned, roChk.checked))
            );
          } catch (err) { toast(err.message, 'error'); }
        });
      }
    );
  }

  async function openHealthModal() {
    if (!state.status?.active_project) return;
    try {
      const env = await api('/api/code/health');
      const d = env.data;
      setHealthDot(d.overall);
      openModal(
        `${t('topbar.health')} — ${d.overall}`,
        `<div class="list-stack">${(d.checks || [])
          .map(
            (c) => `
          <div class="card">
            <div class="row gap-sm">
              <span class="badge ${c.light === 'GREEN' ? 'badge-green' : c.light === 'YELLOW' ? 'badge-amber' : 'badge-red'}">${escHtml(c.light)}</span>
              <strong>${escHtml(c.title)}</strong>
            </div>
            <div class="small muted mt-sm">${escHtml(c.summary)}</div>
            ${(c.details || []).length ? `<pre class="code-pre mt-sm">${escHtml(c.details.join('\n'))}</pre>` : ''}
          </div>`
          )
          .join('')}</div>`
      );
    } catch (err) { toast(err.message, 'error'); }
  }

  async function openCheckpointModal() {
    if (!state.status?.active_project) return;
    const ro = !!state.status.read_only;
    let items = [];
    try {
      const env = await api('/api/checkpoints');
      items = env.data || [];
    } catch (err) { return toast(err.message, 'error'); }

    openModal(
      t('modal.checkpointTitle'),
      `
      <div class="row gap-sm">
        <input id="cp-note" class="input" style="flex:1" placeholder="${escHtml(t('modal.checkpointNote'))}" ${ro ? 'disabled' : ''} />
        <button id="btn-cp-create" class="btn btn-primary" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('modal.createCheckpoint'))}</button>
      </div>
      <div id="cp-preview-box"></div>
      <div class="list-stack">
        ${items
          .map(
            (cp) => `
          <div class="list-item">
            <div>
              <strong>${escHtml(cp.note)}</strong>
              <div class="small muted mono">${escHtml(cp.id)} · ${escHtml(cp.timestamp_utc)} · ${escHtml(cp.branch)}</div>
            </div>
            <div class="row gap-sm">
              <button class="btn btn-ghost small" data-rb-preview="${escHtml(cp.id)}" type="button">${escHtml(t('modal.previewRollback'))}</button>
              <button class="btn btn-danger-ghost small" data-rb-apply="${escHtml(cp.id)}" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('modal.applyRollback'))}</button>
            </div>
          </div>`
          )
          .join('') || '<p class="muted small">No checkpoints yet.</p>'}
      </div>`,
      (body) => {
        body.querySelector('#btn-cp-create')?.addEventListener('click', async () => {
          try {
            await api('/api/checkpoints', { method: 'POST', body: { note: body.querySelector('#cp-note').value } });
            toast('Checkpoint created.', 'ok');
            openCheckpointModal();
          } catch (err) { toast(err.message, 'error'); }
        });
        body.querySelectorAll('[data-rb-preview]').forEach((btn) =>
          btn.addEventListener('click', async () => {
            try {
              const env = await api('/api/checkpoints/rollback', { method: 'POST', body: { id: btn.dataset.rbPreview, dry_run: true } });
              body.querySelector('#cp-preview-box').innerHTML = `<pre class="code-pre">${escHtml(JSON.stringify(env.data, null, 2))}</pre>`;
            } catch (err) { toast(err.message, 'error'); }
          })
        );
        body.querySelectorAll('[data-rb-apply]').forEach((btn) =>
          btn.addEventListener('click', async () => {
            try {
              await api('/api/checkpoints/rollback', { method: 'POST', body: { id: btn.dataset.rbApply, dry_run: false } });
              toast('Rollback applied cleanly.', 'ok');
              closeModal();
            } catch (err) { toast(err.message, 'error'); }
          })
        );
      }
    );
  }

  async function openHandoffModal(budget = 800) {
    if (!state.status?.active_project) return;
    try {
      const data = await api(`/api/handoff?budget=${budget}`);
      openModal(
        t('modal.handoffTitle'),
        `
        <div class="row gap-sm">
          <label class="small muted">Token Budget:</label>
          <select id="handoff-budget" class="select-compact">
            ${[500, 800, 1200, 2000].map((b) => `<option value="${b}" ${b === budget ? 'selected' : ''}>${b}</option>`).join('')}
          </select>
          <span class="spacer"></span>
          <button id="btn-copy-handoff" class="btn btn-primary" type="button">${escHtml(t('modal.copyHandoff'))}</button>
        </div>
        <pre class="code-pre">${escHtml(data.text || '')}</pre>`,
        (body) => {
          body.querySelector('#handoff-budget').addEventListener('change', (ev) => openHandoffModal(Number(ev.target.value)));
          body.querySelector('#btn-copy-handoff').addEventListener('click', () => copyText(data.text || ''));
        }
      );
    } catch (err) { toast(err.message, 'error'); }
  }

  async function openSettingsModal() {
    if (!state.status?.active_project) return renderFolderPicker(null);
    const ro = !!state.status.read_only;
    try {
      const [detect, doctor, exts] = await Promise.all([
        api('/api/agents/detect'),
        api('/api/agents/doctor'),
        api('/api/extensions'),
      ]);
      const curMode = detect.project_mode || 'active';

      openModal(
        t('modal.settingsTitle'),
        `
        <div class="card">
          <div class="row gap-sm">
            <strong>${escHtml(t('modal.projectMode'))}:</strong>
            <select id="proj-mode-sel" class="select-compact" ${ro ? 'disabled' : ''}>
              <option value="active" ${curMode === 'active' ? 'selected' : ''}>Active</option>
              <option value="read_only" ${curMode === 'read_only' ? 'selected' : ''}>Read-Only</option>
              <option value="paused" ${curMode === 'paused' ? 'selected' : ''}>Paused</option>
            </select>
            <button id="btn-attach-dry" class="btn btn-ghost small" type="button">${escHtml(t('modal.attachPreview'))}</button>
            <button id="btn-attach-run" class="btn btn-primary small" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('modal.attachApply'))}</button>
            <button id="btn-detach-dry" class="btn btn-ghost small" type="button">${escHtml(t('modal.detachPreview'))}</button>
            <button id="btn-detach-run" class="btn btn-danger-ghost small" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('modal.detachApply'))}</button>
          </div>
          <div id="settings-preview-out" class="mt-sm"></div>
        </div>
        <div class="card">
          <h4>${escHtml(t('modal.configuredAccess'))}</h4>
          <div class="row gap-sm mt-sm">
            <select id="agent-host-sel" class="select-compact">
              <option value="auto">auto</option>
              <option value="antigravity">antigravity</option>
              <option value="claude-code">claude-code</option>
              <option value="codex">codex</option>
              <option value="generic">generic</option>
              <option value="all">all</option>
            </select>
            <button id="btn-agent-init-dry" class="btn btn-ghost small" type="button">Connect (Dry-Run)</button>
            <button id="btn-agent-init-run" class="btn btn-primary small" type="button" ${ro ? 'disabled' : ''}>Connect</button>
            <button id="btn-agent-disc-dry" class="btn btn-ghost small" type="button">Disconnect (Dry-Run)</button>
            <button id="btn-agent-disc-run" class="btn btn-danger-ghost small" type="button" ${ro ? 'disabled' : ''}>Disconnect</button>
          </div>
          <table class="data-table mt-sm">
            <thead><tr><th>Host</th><th>Scope</th><th>Status</th><th>Path</th></tr></thead>
            <tbody>
              ${(detect.configured_access || [])
                .map((c) => {
                  const statusBadge = c.binary_matches_current === false
                    ? '<span class="badge badge-amber">stale binary</span>'
                    : '<span class="badge badge-green">installed</span>';
                  return `<tr><td>${escHtml(c.host_id)}</td><td><span class="badge">${escHtml(c.scope_label || c.scope)}</span></td><td>${statusBadge}</td><td class="mono small">${escHtml(c.config_path)}</td></tr>`;
                })
                .join('') || '<tr><td colspan="4" class="muted">None configured</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="card">
          <h4>${escHtml(t('modal.observedAccess'))}</h4>
          <table class="data-table mt-sm">
            <thead><tr><th>Client</th><th>Version</th><th>Calls</th><th>Last Seen</th></tr></thead>
            <tbody>
              ${(detect.observed_access || [])
                .map((o) => `<tr><td class="mono">${escHtml(o.client_name)}</td><td class="mono small">${escHtml(o.client_version)}</td><td class="mono">${fmtNum(o.tool_calls)}</td><td class="mono small">${escHtml(o.last_seen_utc)}</td></tr>`)
                .join('') || '<tr><td colspan="4" class="muted">No observed MCP calls recorded yet.</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="card">
          <h4>${escHtml(t('modal.extensionsTitle'))}</h4>
          <p class="muted small mt-sm">${escHtml(t('modal.extensionsHint'))}</p>
          <table class="data-table mt-sm">
            <thead><tr><th>Extension</th><th>${escHtml(t('modal.extStatus'))}</th><th>${escHtml(t('modal.extProject'))}</th><th>${escHtml(t('modal.extGlobal'))}</th></tr></thead>
            <tbody>
              ${(exts.extensions || [])
                .map((ext) => {
                  const dis = ro || !ext.known ? 'disabled' : '';
                  const isLang = ext.kind === 'language_parser';
                  const extList = Array.isArray(ext.extensions) ? ext.extensions : [];
                  const langTags = isLang
                    ? ` <span class="badge badge-blue">language-parser</span>${extList.length ? ` <span class="badge" title="${escHtml(extList.join(', '))}">${fmtNum(extList.length)} ${escHtml(t('modal.extExtensionsCount'))}</span>` : ''}`
                    : '';
                  let statusHtml = `<span class="badge">${escHtml(ext.transport)}</span>`;
                  if (isLang) {
                    const detailAttr = ext.health_detail ? ` title="${escHtml(ext.health_detail)}"` : '';
                    if (ext.health === 'ready') {
                      statusHtml = `<span class="badge badge-ext-ready"${detailAttr}>${escHtml(t('modal.extHealthReady'))}</span>`;
                    } else if (ext.health === 'unavailable') {
                      statusHtml = `<span class="badge badge-amber"${detailAttr}>${escHtml(t('modal.extHealthUnavailable'))}</span>`;
                    } else if (ext.health === 'misconfigured') {
                      statusHtml = `<span class="badge badge-red"${detailAttr}>${escHtml(t('modal.extHealthMisconfigured'))}</span>`;
                    } else {
                      statusHtml = `<span class="badge"${detailAttr}>${escHtml(t('modal.extHealthDisabled'))}</span>`;
                    }
                  }
                  const detailNote = isLang && ext.health_detail && (ext.health === 'unavailable' || ext.health === 'misconfigured')
                    ? `<div class="muted small mono">${escHtml(ext.health_detail)}</div>`
                    : '';
                  return `<tr>
                    <td><div class="mono small"><strong>${escHtml(ext.id)}</strong>${langTags}</div><div class="muted small">${escHtml(ext.description)}</div>${detailNote}</td>
                    <td>${statusHtml}</td>
                    <td><input type="checkbox" data-ext-toggle="${escHtml(ext.id)}" data-ext-scope="project" ${ext.enabled_project ? 'checked' : ''} ${isLang ? 'disabled' : dis} /></td>
                    <td><input type="checkbox" data-ext-toggle="${escHtml(ext.id)}" data-ext-scope="global" ${ext.enabled_global ? 'checked' : ''} ${dis} /></td>
                  </tr>`;
                })
                .join('')}
            </tbody>
          </table>
        </div>
        <div class="card">
          <h4>${escHtml(t('modal.doctorTitle'))} (${escHtml(doctor.overall)})</h4>
          <div class="list-stack mt-sm">
            ${(doctor.checks || [])
              .map((ch) => `<div class="small"><span class="badge ${ch.severity === 'ok' ? 'badge-green' : ch.severity === 'warning' ? 'badge-amber' : 'badge-red'}">${escHtml(ch.severity)}</span> <strong>${escHtml(ch.name)}</strong>: <span class="muted">${escHtml(ch.message)}</span></div>`)
              .join('')}
          </div>
        </div>`,
        (body) => {
          const out = body.querySelector('#settings-preview-out');
          const bindPost = (sel, url, bodyFn, onOk) =>
            body.querySelector(sel)?.addEventListener('click', async () => {
              try {
                const r = await api(url, { method: 'POST', body: bodyFn() });
                onOk(r);
              } catch (err) { toast(err.message, 'error'); }
            });
          const showPre = (r) => { out.innerHTML = `<pre class="code-pre">${escHtml(JSON.stringify(r, null, 2))}</pre>`; };
          body.querySelector('#proj-mode-sel')?.addEventListener('change', async (ev) => {
            try {
              await api('/api/projects/mode', { method: 'POST', body: { mode: ev.target.value } });
              toast('Project mode saved.', 'ok');
              refreshStatus();
            } catch (err) { toast(err.message, 'error'); }
          });
          bindPost('#btn-attach-dry', '/api/projects/attach', () => ({ dry_run: true }), showPre);
          bindPost('#btn-attach-run', '/api/projects/attach', () => ({ dry_run: false }), () => { toast('Project attached.', 'ok'); refreshStatus(); openSettingsModal(); });
          bindPost('#btn-detach-dry', '/api/projects/detach', () => ({ dry_run: true, purge: false }), showPre);
          bindPost('#btn-detach-run', '/api/projects/detach', () => ({ dry_run: false, purge: false }), () => { toast('Project detached (blueprint & memory preserved).', 'ok'); refreshStatus(); openSettingsModal(); });
          body.querySelectorAll('[data-ext-toggle]').forEach((chk) =>
            chk.addEventListener('change', async () => {
              try {
                await api('/api/extensions/toggle', { method: 'POST', body: { id: chk.dataset.extToggle, scope: chk.dataset.extScope, enabled: chk.checked } });
                toast(`Extension ${chk.dataset.extToggle} (${chk.dataset.extScope}) updated.`, 'ok');
                openSettingsModal();
              } catch (err) {
                chk.checked = !chk.checked;
                toast(err.message, 'error');
              }
            })
          );
          const selectedHost = () => body.querySelector('#agent-host-sel').value;
          const discHost = () => (selectedHost() === 'auto' ? 'all' : selectedHost());
          bindPost('#btn-agent-init-dry', '/api/agents/init', () => ({ host: selectedHost(), dry_run: true }), showPre);
          bindPost('#btn-agent-init-run', '/api/agents/init', () => ({ host: selectedHost(), dry_run: false }), () => { toast('Host adapter connected.', 'ok'); openSettingsModal(); });
          bindPost('#btn-agent-disc-dry', '/api/agents/disconnect', () => ({ host: discHost(), dry_run: true }), showPre);
          bindPost('#btn-agent-disc-run', '/api/agents/disconnect', () => ({ host: discHost(), dry_run: false }), () => { toast('Host adapter disconnected.', 'ok'); openSettingsModal(); });
        }
      );
    } catch (err) { toast(err.message, 'error'); }
  }

  function bindGlobalEvents() {
    const views = window.KlensViews || {};
    $('btn-project-picker').addEventListener('click', () => {
      state.pickerReadOnly = !!state.status?.cli_read_only_locked;
      renderFolderPicker(state.status?.active_project?.path || null);
    });
    $('btn-welcome-browse').addEventListener('click', () => {
      state.pickerReadOnly = !!state.status?.cli_read_only_locked;
      renderFolderPicker(null);
    });
    $('btn-health').addEventListener('click', openHealthModal);
    $('btn-checkpoint').addEventListener('click', openCheckpointModal);
    $('btn-handoff').addEventListener('click', () => openHandoffModal(800));
    $('btn-settings').addEventListener('click', openSettingsModal);
    $('modal-close').addEventListener('click', closeModal);
    $('modal-backdrop').addEventListener('click', (ev) => {
      if (ev.target === $('modal-backdrop')) closeModal();
    });

    $('select-lang').addEventListener('change', async (ev) => {
      try {
        const lang = ev.target.value;
        await api('/api/settings/lang', { method: 'PUT', body: { ui_lang: lang } });
        await loadI18n(lang);
        if (state.status?.active_project) switchTab(state.activeTab, true);
      } catch (err) { toast(err.message, 'error'); }
    });

    $('btn-shutdown').addEventListener('click', async () => {
      if (state.isShutDown) return;
      try {
        await api('/api/shutdown', { method: 'POST', body: {} });
        enterShutdownState();
      } catch (err) { toast(err.message, 'error'); }
    });

    document.querySelectorAll('.tab-btn').forEach((btn) =>
      btn.addEventListener('click', () => switchTab(btn.dataset.tab, true))
    );
    document.querySelectorAll('.subtab-btn').forEach((btn) =>
      btn.addEventListener('click', () => {
        state.memorySubtab = btn.dataset.subtab;
        document.querySelectorAll('.subtab-btn').forEach((b) => b.classList.toggle('active', b === btn));
        $('subtab-vault').classList.toggle('hidden', state.memorySubtab !== 'vault');
        $('subtab-runs').classList.toggle('hidden', state.memorySubtab !== 'runs');
        if (state.memorySubtab === 'vault' && views.loadMemoryList) views.loadMemoryList();
        else if (views.loadRunsList) views.loadRunsList();
      })
    );

    $('code-filter').addEventListener('input', () => views.renderCodeGraph && views.renderCodeGraph());
    $('btn-refresh-graph').addEventListener('click', () => views.loadCodeGraph && views.loadCodeGraph());

    $('mem-filter-group').querySelectorAll('.pill').forEach((pill) =>
      pill.addEventListener('click', () => {
        state.memFilter = pill.dataset.filter;
        $('mem-filter-group').querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === pill));
        views.loadMemoryList && views.loadMemoryList();
      })
    );
    $('mem-search').addEventListener('input', (ev) => {
      state.memSearch = ev.target.value;
      views.loadMemoryList && views.loadMemoryList();
    });
    $('btn-mem-verify').addEventListener('click', async () => {
      try {
        const env = await api('/api/memory/verify');
        toast(`Verified ${env.data.total_notes} note(s): ${env.data.stale_count} STALE.`, env.data.stale_count ? 'error' : 'ok');
        views.loadMemoryList && views.loadMemoryList();
      } catch (err) { toast(err.message, 'error'); }
    });
    $('btn-mem-obsidian').addEventListener('click', () => {
      if (state.memDir) copyText(state.memDir);
    });
    $('btn-mem-new').addEventListener('click', () => views.openNewNoteModal && views.openNewNoteModal());

    $('stats-range-group').querySelectorAll('.pill').forEach((pill) =>
      pill.addEventListener('click', () => {
        state.statsRange = pill.dataset.range;
        $('stats-range-group').querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === pill));
        views.loadStats && views.loadStats();
      })
    );
    $('stats-scope-group').querySelectorAll('.pill').forEach((pill) =>
      pill.addEventListener('click', () => {
        state.statsScope = pill.dataset.scope;
        $('stats-scope-group').querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === pill));
        views.loadStats && views.loadStats();
      })
    );
  }

  window.KlensCore = { state, $, escHtml, fmtNum, t, toast, copyText, api, openModal, closeModal };
  window.KlensViews = window.KlensViews || {};

  document.addEventListener('DOMContentLoaded', async () => {
    initTheme();
    bindGlobalEvents();
    await loadI18n('en');
    try {
      await refreshStatus();
    } catch {
      // 401 handler already renders auth notice.
    }
  });
})();
