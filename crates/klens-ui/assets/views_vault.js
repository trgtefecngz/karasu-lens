(() => {
  'use strict';

  function core() {
    return window.KlensCore;
  }

  // ==================== TAB 3: MEMORY VAULT & RUNS ====================
  let vaultControlsBound = false;

  function syncVaultReadOnlyState() {
    const { state, $ } = core();
    const ro = !!state.status?.read_only;
    const refreshAllBtn = $('btn-mem-refresh-all');
    if (refreshAllBtn) refreshAllBtn.disabled = ro;
    const exportBtn = $('btn-mem-export');
    if (exportBtn) exportBtn.disabled = false;
  }

  function ensureVaultControlsBound() {
    if (vaultControlsBound) return;
    const { $ } = core();
    const exportBtn = $('btn-mem-export');
    if (exportBtn) exportBtn.addEventListener('click', openExportMemoryModal);
    const refreshAllBtn = $('btn-mem-refresh-all');
    if (refreshAllBtn) refreshAllBtn.addEventListener('click', openRefreshAllModal);
    vaultControlsBound = true;
  }

  function triggerOfflineDownload(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function openExportMemoryModal() {
    const { state, escHtml, t, toast, copyText, api, openModal } = core();
    let format = 'md';
    let staleOnly = state.memFilter === 'stale';
    let lastPayload = null;

    openModal(
      t('mem.exportTitle'),
      `
      <div class="row gap-sm">
        <div class="pill-group" id="mem-export-fmt-group">
          <button class="pill active" data-exp-fmt="md" type="button">${escHtml(t('mem.exportMarkdown'))}</button>
          <button class="pill" data-exp-fmt="json" type="button">${escHtml(t('mem.exportJson'))}</button>
        </div>
        <label class="row gap-sm small muted" style="cursor:pointer">
          <input id="mem-export-stale-only" type="checkbox" ${staleOnly ? 'checked' : ''} />
          <span>${escHtml(t('mem.exportStaleOnly'))}</span>
        </label>
        <span class="spacer"></span>
        <span id="mem-export-meta" class="small muted mono"></span>
      </div>
      <div id="mem-export-warnings" class="small muted mt-sm"></div>
      <pre id="mem-export-preview" class="code-pre mt-sm" style="max-height:360px"></pre>
      <div class="row gap-sm mt-md">
        <span class="spacer"></span>
        <button id="btn-mem-export-copy" class="btn btn-ghost" type="button">${escHtml(t('mem.exportCopy'))}</button>
        <button id="btn-mem-export-dl" class="btn btn-primary" type="button">${escHtml(t('mem.exportDownload'))}</button>
      </div>`,
      (body) => {
        const metaEl = body.querySelector('#mem-export-meta');
        const warnEl = body.querySelector('#mem-export-warnings');
        const preEl = body.querySelector('#mem-export-preview');
        const fmtGroup = body.querySelector('#mem-export-fmt-group');
        const staleChk = body.querySelector('#mem-export-stale-only');

        async function fetchExport() {
          const q = new URLSearchParams();
          q.set('format', format);
          if (state.memFilter !== 'all' && state.memFilter !== 'stale') {
            q.set('kind', state.memFilter);
          }
          if (staleOnly) q.set('stale_only', 'true');
          try {
            const data = await api(`/api/memory/export?${q.toString()}`);
            lastPayload = data;
            metaEl.textContent = `notes=${data.total_notes} · stale=${data.stale_count} · redactions=${data.redactions_count}`;
            const warnings = data.warnings || [];
            warnEl.innerHTML = warnings.length
              ? warnings.map((w) => `<div>! ${escHtml(w)}</div>`).join('')
              : '';
            preEl.textContent = data.content || '';
          } catch (err) {
            lastPayload = null;
            preEl.textContent = err.message;
            toast(err.message, 'error');
          }
        }

        fmtGroup.querySelectorAll('[data-exp-fmt]').forEach((btn) =>
          btn.addEventListener('click', () => {
            format = btn.dataset.expFmt || 'md';
            fmtGroup.querySelectorAll('[data-exp-fmt]').forEach((b) => b.classList.toggle('active', b === btn));
            fetchExport();
          })
        );
        staleChk.addEventListener('change', () => {
          staleOnly = staleChk.checked;
          fetchExport();
        });
        body.querySelector('#btn-mem-export-copy').addEventListener('click', () => {
          if (lastPayload) copyText(lastPayload.content || '');
        });
        body.querySelector('#btn-mem-export-dl').addEventListener('click', () => {
          if (!lastPayload) return;
          const mime = format === 'json' ? 'application/json;charset=utf-8' : 'text/markdown;charset=utf-8';
          triggerOfflineDownload(lastPayload.filename || `klens-memory-export.${format}`, lastPayload.content || '', mime);
        });

        fetchExport();
      }
    );
  }

  function openRefreshAllModal() {
    const { state, escHtml, t, toast, api, openModal, closeModal } = core();
    if (state.status?.read_only) return toast(t('toast.readOnlyBlocked'), 'error');
    let staleOnly = true;

    openModal(
      t('mem.refreshAllTitle'),
      `
      <div class="row gap-sm">
        <label class="row gap-sm small muted" style="cursor:pointer">
          <input id="mem-refresh-stale-only" type="checkbox" checked />
          <span>${escHtml(t('mem.refreshAllStaleOnly'))}</span>
        </label>
        <span class="spacer"></span>
        <button id="btn-mem-refresh-preview" class="btn btn-ghost small" type="button">${escHtml(t('mem.refreshAllPreview'))}</button>
      </div>
      <div id="mem-refresh-summary" class="mt-md"></div>
      <div class="row gap-sm mt-md">
        <span class="spacer"></span>
        <button id="btn-mem-refresh-apply" class="btn btn-primary" type="button">${escHtml(t('mem.refreshAllApply'))}</button>
      </div>`,
      (body) => {
        const staleChk = body.querySelector('#mem-refresh-stale-only');
        const summaryEl = body.querySelector('#mem-refresh-summary');

        function renderRefreshReport(env) {
          const d = env.data || {};
          const refreshed = d.refreshed || [];
          const unchanged = d.unchanged || [];
          const failed = d.failed || [];
          const parts = [
            `<div class="small mono">scanned=${d.total_scanned ?? 0} · refreshed=${refreshed.length} · unchanged=${unchanged.length} · failed=${failed.length}${d.dry_run ? ' (dry-run)' : ''}</div>`,
          ];
          if (!refreshed.length && !failed.length) {
            parts.push(`<p class="muted small mt-sm">${escHtml(t('mem.refreshAllEmpty'))}</p>`);
          }
          if (refreshed.length) {
            parts.push(
              `<div class="list-stack mt-sm">${refreshed
                .map((r) => `<div class="small mono"><span class="badge badge-green">${d.dry_run ? 'PLAN' : 'OK'}</span> ${escHtml(r.id)} (${escHtml(r.previous_trust)} -&gt; ${escHtml(r.new_trust)}, anchors=${r.updated_anchors})</div>`)
                .join('')}</div>`
            );
          }
          if (failed.length) {
            parts.push(
              `<div class="list-stack mt-sm">${failed
                .map((f) => `<div class="small mono"><span class="badge badge-red">FAILED</span> ${escHtml(f.id)}: ${escHtml(f.reason)}</div>`)
                .join('')}</div>`
            );
          }
          summaryEl.innerHTML = parts.join('');
        }

        async function runBatch(dryRun) {
          try {
            const env = await api('/api/memory/refresh-all', {
              method: 'POST',
              body: { stale_only: staleOnly, dry_run: dryRun },
            });
            renderRefreshReport(env);
            if (!dryRun) {
              const d = env.data || {};
              const refN = (d.refreshed || []).length;
              const failN = (d.failed || []).length;
              toast(
                `Refreshed ${refN} note(s), unchanged ${(d.unchanged || []).length}, failed ${failN}.`,
                failN ? 'error' : 'ok'
              );
              loadMemoryList();
              if (!failN) closeModal();
            }
          } catch (err) {
            summaryEl.innerHTML = `<p class="muted">${escHtml(err.message)}</p>`;
            toast(err.message, 'error');
          }
        }

        staleChk.addEventListener('change', () => {
          staleOnly = staleChk.checked;
          runBatch(true);
        });
        body.querySelector('#btn-mem-refresh-preview').addEventListener('click', () => runBatch(true));
        body.querySelector('#btn-mem-refresh-apply').addEventListener('click', () => runBatch(false));

        runBatch(true);
      }
    );
  }

  async function loadMemoryList() {
    ensureVaultControlsBound();
    syncVaultReadOnlyState();
    const { state, $, escHtml, t, toast, api } = core();
    const q = new URLSearchParams();
    if (state.memFilter === 'stale') q.set('stale_only', 'true');
    else if (state.memFilter !== 'all') q.set('kind', state.memFilter);
    if (state.memSearch.trim()) q.set('q', state.memSearch.trim());

    try {
      const data = await api(`/api/memory?${q.toString()}`);
      state.memDir = data.memory_dir || '';
      const entries = data.entries || [];
      const listEl = $('mem-list');
      if (!entries.length) {
        listEl.innerHTML = `<p class="muted">${escHtml(t('mem.noNotes'))}</p>`;
        $('mem-detail').innerHTML = '';
        return;
      }
      listEl.innerHTML = `<div class="list-stack">${entries
        .map((e) => {
          const isStale = e.trust === 'STALE';
          return `
          <div class="list-item ${state.selectedNoteId === e.id ? 'active' : ''}" data-note-id="${escHtml(e.id)}">
            <div>
              <strong>${escHtml(e.title)}</strong>
              <div class="small muted mono">${escHtml(e.id)} · ${(e.tags || []).map((tg) => `#${escHtml(tg)}`).join(' ')}</div>
            </div>
            <div class="row gap-sm">
              <span class="badge">${escHtml(e.kind)}</span>
              <span class="badge ${isStale ? 'badge-red' : 'badge-green'}">${escHtml(e.trust)}</span>
            </div>
          </div>`;
        })
        .join('')}</div>`;
      listEl.querySelectorAll('[data-note-id]').forEach((el) =>
        el.addEventListener('click', () => loadMemoryDetail(el.dataset.noteId))
      );
      const nextId = state.selectedNoteId && entries.some((e) => e.id === state.selectedNoteId)
        ? state.selectedNoteId
        : entries[0].id;
      loadMemoryDetail(nextId);
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function loadMemoryDetail(id) {
    const { state, $, escHtml, t, toast, copyText, api } = core();
    state.selectedNoteId = id;
    const ro = !!state.status?.read_only;
    try {
      const data = await api(`/api/memory/${encodeURIComponent(id)}`);
      const env = data.envelope;
      const note = env.data.note;
      const isStale = env.trust === 'STALE';
      $('mem-detail').innerHTML = `
        <div class="card-header">
          <div>
            <h3>${escHtml(note.frontmatter.title)}</h3>
            <div class="small muted mono">${escHtml(note.frontmatter.id)}</div>
          </div>
          <span class="badge ${isStale ? 'badge-red' : 'badge-green'}">${escHtml(env.trust)}</span>
        </div>
        <div class="row gap-sm">
          <button id="btn-note-copy" class="btn btn-ghost small" type="button">${escHtml(t('mem.copyMd'))}</button>
          <button id="btn-note-refresh" class="btn btn-ghost small" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('mem.refreshAnchors'))}</button>
          <button id="btn-note-delete" class="btn btn-danger-ghost small" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('mem.delete'))}</button>
        </div>
        <div class="mt-md">
          <label class="small muted">Title</label>
          <input id="edit-note-title" class="input mt-sm" style="width:100%" value="${escHtml(note.frontmatter.title)}" ${ro ? 'disabled' : ''} />
        </div>
        <div class="row gap-sm mt-sm">
          <select id="edit-note-kind" class="select-compact" ${ro ? 'disabled' : ''}>
            ${['decision', 'bugfix', 'architecture', 'feedback', 'constraint'].map((k) => `<option value="${k}" ${note.frontmatter.kind === k ? 'selected' : ''}>${k}</option>`).join('')}
          </select>
          <input id="edit-note-tags" class="input" style="flex:1" value="${escHtml((note.frontmatter.tags || []).join(', '))}" placeholder="tag1, tag2" ${ro ? 'disabled' : ''} />
        </div>
        <div class="mt-sm">
          <label class="small muted">Markdown Body</label>
          <textarea id="edit-note-body" class="textarea mt-sm" style="min-height:160px" ${ro ? 'disabled' : ''}>${escHtml(note.body || '')}</textarea>
        </div>
        <div class="mt-sm">
          <div class="small muted">${escHtml(t('mem.anchors'))}:</div>
          <div class="list-stack mt-sm">
            ${(env.data.verification?.anchor_checks || [])
              .map((a) => `<div class="small mono"><span class="badge ${a.fresh ? 'badge-green' : 'badge-red'}">${a.fresh ? 'OK' : 'STALE'}</span> ${escHtml(a.path)}${a.symbol ? `#${escHtml(a.symbol)}` : ''}</div>`)
              .join('') || '<span class="small muted">None</span>'}
          </div>
        </div>
        <div class="row mt-md"><span class="spacer"></span><button id="btn-note-save" class="btn btn-primary" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('mem.save'))}</button></div>`;

      $('btn-note-copy').addEventListener('click', () => copyText(data.markdown || ''));
      $('btn-note-refresh').addEventListener('click', async () => {
        try {
          await api(`/api/memory/${encodeURIComponent(id)}/refresh`, { method: 'POST', body: {} });
          toast('Anchors refreshed with live BLAKE3 hashes.', 'ok');
          loadMemoryList();
        } catch (err) { toast(err.message, 'error'); }
      });
      $('btn-note-delete').addEventListener('click', async () => {
        try {
          await api(`/api/memory/${encodeURIComponent(id)}`, { method: 'DELETE' });
          state.selectedNoteId = null;
          toast('Note deleted.', 'ok');
          loadMemoryList();
        } catch (err) { toast(err.message, 'error'); }
      });
      $('btn-note-save').addEventListener('click', async () => {
        try {
          const tags = $('edit-note-tags').value.split(',').map((s) => s.trim()).filter(Boolean);
          await api(`/api/memory/${encodeURIComponent(id)}`, {
            method: 'PUT',
            body: { title: $('edit-note-title').value.trim(), kind: $('edit-note-kind').value, tags, body: $('edit-note-body').value },
          });
          toast('Note updated.', 'ok');
          loadMemoryList();
        } catch (err) { toast(err.message, 'error'); }
      });
    } catch (err) {
      $('mem-detail').innerHTML = `<p class="muted">${escHtml(err.message)}</p>`;
    }
  }

  function openNewNoteModal() {
    const { state, escHtml, t, toast, api, openModal, closeModal } = core();
    if (state.status?.read_only) return toast(t('toast.readOnlyBlocked'), 'error');
    openModal(
      t('mem.newNote'),
      `
      <input id="new-note-title" class="input" placeholder="Title" />
      <div class="row gap-sm">
        <select id="new-note-kind" class="select-compact">
          <option value="decision">decision</option>
          <option value="architecture">architecture</option>
          <option value="bugfix">bugfix</option>
          <option value="feedback">feedback</option>
          <option value="constraint">constraint</option>
        </select>
        <input id="new-note-anchors" class="input" style="flex:1" placeholder="Anchors (comma-sep: src/main.rs, src/lib.rs#fn)" />
      </div>
      <input id="new-note-tags" class="input" placeholder="Tags (comma-sep)" />
      <textarea id="new-note-body" class="textarea" style="min-height:140px" placeholder="Markdown body..."></textarea>
      <div class="row"><span class="spacer"></span><button id="btn-new-note-submit" class="btn btn-primary" type="button">${escHtml(t('mem.save'))}</button></div>`,
      (body) => {
        body.querySelector('#btn-new-note-submit').addEventListener('click', async () => {
          const title = body.querySelector('#new-note-title').value.trim();
          if (!title) return toast('Title required', 'error');
          const anchors = body.querySelector('#new-note-anchors').value.split(',').map((s) => s.trim()).filter(Boolean);
          const tags = body.querySelector('#new-note-tags').value.split(',').map((s) => s.trim()).filter(Boolean);
          try {
            await api('/api/memory', {
              method: 'POST',
              body: { title, kind: body.querySelector('#new-note-kind').value, anchors, tags, body: body.querySelector('#new-note-body').value },
            });
            closeModal();
            toast('Memory note created.', 'ok');
            loadMemoryList();
          } catch (err) { toast(err.message, 'error'); }
        });
      }
    );
  }

  let runsStatusFilter = 'all';
  let runsSearchQuery = '';
  let runViewMode = 'filtered';
  let runDetailSeq = 0;
  let runsControlsBound = false;

  function ensureRunsControlsBound() {
    if (runsControlsBound) return;
    const { $ } = core();
    const statusGroup = $('runs-status-group');
    const searchInput = $('runs-search');
    if (statusGroup) {
      statusGroup.querySelectorAll('.pill').forEach((pill) =>
        pill.addEventListener('click', () => {
          runsStatusFilter = pill.dataset.runStatus || 'all';
          statusGroup.querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === pill));
          renderRunsTable();
        })
      );
    }
    if (searchInput) {
      searchInput.addEventListener('input', (ev) => {
        runsSearchQuery = ev.target.value || '';
        renderRunsTable();
      });
    }
    runsControlsBound = true;
  }

  function setRunsCompareLayout(active) {
    const split = document.querySelector('#subtab-runs .split-layout');
    if (split) split.classList.toggle('runs-compare-active', !!active);
  }

  function updateRunsActiveRow(runId) {
    const { $ } = core();
    const tbody = $('runs-tbody');
    if (!tbody) return;
    tbody.querySelectorAll('[data-run-id]').forEach((tr) => {
      tr.classList.toggle('active', tr.dataset.runId === runId);
    });
  }

  function matchesRunFilter(r) {
    if (runsStatusFilter === 'ok' && r.exit_code !== 0) return false;
    if (runsStatusFilter === 'failed' && r.exit_code === 0) return false;
    const q = runsSearchQuery.trim().toLowerCase();
    if (!q) return true;
    const haystack = [
      r.command || '',
      r.filter_used || '',
      r.run_id || '',
      String(r.exit_code ?? ''),
      `exit ${r.exit_code ?? ''}`,
    ]
      .join(' ')
      .toLowerCase();
    return haystack.includes(q);
  }

  function renderRunsTable() {
    const { state, $, escHtml, fmtNum, t } = core();
    const runs = state.runsList || [];
    const filtered = runs.filter(matchesRunFilter);
    const countEl = $('runs-count');
    if (countEl) countEl.textContent = `${filtered.length} / ${runs.length}`;

    const tbody = $('runs-tbody');
    if (!runs.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted">${escHtml(t('mem.runsEmpty'))}</td></tr>`;
      $('run-detail').innerHTML = '';
      setRunsCompareLayout(false);
      return;
    }
    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted">${escHtml(t('mem.runsNoMatch'))}</td></tr>`;
      $('run-detail').innerHTML = '';
      setRunsCompareLayout(false);
      return;
    }

    const nextId = state.selectedRunId && filtered.some((r) => r.run_id === state.selectedRunId)
      ? state.selectedRunId
      : filtered[0].run_id;

    tbody.innerHTML = filtered
      .map((r) => {
        const savedPct = r.est_raw_tokens > 0
          ? (((r.est_raw_tokens - r.est_filtered_tokens) / r.est_raw_tokens) * 100).toFixed(1)
          : '0.0';
        return `
        <tr class="${r.run_id === nextId ? 'active' : ''}" data-run-id="${escHtml(r.run_id)}">
          <td class="mono small">${escHtml(r.command)}</td>
          <td><span class="badge ${r.exit_code === 0 ? 'badge-green' : 'badge-red'}">${r.exit_code}</span></td>
          <td class="mono small">${fmtNum(r.duration_ms)} ms</td>
          <td class="mono small">${fmtNum(r.est_raw_tokens)} -&gt; ${fmtNum(r.est_filtered_tokens)}</td>
          <td class="mono small">${savedPct}%</td>
        </tr>`;
      })
      .join('');
    tbody.querySelectorAll('[data-run-id]').forEach((tr) =>
      tr.addEventListener('click', () => loadRunDetail(tr.dataset.runId, runViewMode))
    );
    loadRunDetail(nextId, runViewMode);
  }

  async function loadRunsList() {
    ensureRunsControlsBound();
    const { state, toast, api } = core();
    try {
      const env = await api('/api/runs?limit=200');
      state.runsList = env.data || [];
      renderRunsTable();
    } catch (err) { toast(err.message, 'error'); }
  }

  function renderRunHeaderAndTabs(m, mode) {
    const { escHtml, t } = core();
    return `
      <div class="card-header">
        <div>
          <div class="mono"><strong>${escHtml(m.command)}</strong></div>
          <div class="small muted mono">${escHtml(m.run_id)} · ${escHtml(m.timestamp_utc)} · filter=${escHtml(m.filter_used)}</div>
        </div>
        <span class="badge ${m.exit_code === 0 ? 'badge-green' : 'badge-red'}">exit ${m.exit_code}</span>
      </div>
      <div class="row gap-sm mt-sm">
        <button id="btn-run-filtered" class="pill ${mode === 'filtered' ? 'active' : ''}" type="button">${escHtml(t('mem.runFilteredTab'))}</button>
        <button id="btn-run-raw" class="pill ${mode === 'raw' ? 'active' : ''}" type="button">${escHtml(t('mem.runRawTab'))}</button>
        <button id="btn-run-compare" class="pill ${mode === 'compare' ? 'active' : ''}" type="button">${escHtml(t('mem.runCompareTab'))}</button>
        ${mode !== 'compare' ? `<span class="spacer"></span><button id="btn-run-copy" class="btn btn-ghost small" type="button">${escHtml(t('mem.copyOutput'))}</button>` : ''}
      </div>`;
  }

  async function loadRunDetail(runId, modeInput = 'filtered') {
    const { state, $, escHtml, fmtNum, t, copyText, api } = core();
    const mode = modeInput === true
      ? 'raw'
      : modeInput === false
        ? 'filtered'
        : (['filtered', 'raw', 'compare'].includes(modeInput) ? modeInput : 'filtered');

    state.selectedRunId = runId;
    runViewMode = mode;
    state.runRawMode = mode === 'raw';
    updateRunsActiveRow(runId);
    setRunsCompareLayout(mode === 'compare');

    const seq = ++runDetailSeq;
    const emptyText = t('mem.runEmptyOutput');
    try {
      if (mode === 'compare') {
        const [filteredEnv, rawEnv] = await Promise.all([
          api(`/api/runs/${encodeURIComponent(runId)}?raw=false`),
          api(`/api/runs/${encodeURIComponent(runId)}?raw=true`),
        ]);
        if (seq !== runDetailSeq) return;
        const fd = filteredEnv.data;
        const rd = rawEnv.data;
        const m = fd.meta || rd.meta;
        $('run-detail').innerHTML = `
          ${renderRunHeaderAndTabs(m, mode)}
          <div class="run-compare-grid mt-md">
            <div class="run-compare-pane">
              <div class="run-pane-head">
                <div>
                  <strong class="small">${escHtml(t('mem.runFilteredTab'))}</strong>
                  <div class="small muted mono">${fmtNum(m.filtered_bytes)} ${escHtml(t('mem.runBytesLabel'))} · ~${fmtNum(m.est_filtered_tokens)} ${escHtml(t('mem.runTokensUnit'))}</div>
                </div>
                <button id="btn-run-copy-filtered" class="btn btn-ghost small" type="button">${escHtml(t('mem.copyFiltered'))}</button>
              </div>
              <pre class="code-pre">${escHtml(fd.content || emptyText)}</pre>
            </div>
            <div class="run-compare-pane">
              <div class="run-pane-head">
                <div>
                  <strong class="small">${escHtml(t('mem.runRawTab'))}</strong>
                  <div class="small muted mono">${fmtNum(m.raw_bytes)} ${escHtml(t('mem.runBytesLabel'))} · ~${fmtNum(m.est_raw_tokens)} ${escHtml(t('mem.runTokensUnit'))}</div>
                </div>
                <button id="btn-run-copy-raw" class="btn btn-ghost small" type="button">${escHtml(t('mem.copyRaw'))}</button>
              </div>
              <pre class="code-pre">${escHtml(rd.content || emptyText)}</pre>
            </div>
          </div>`;
        $('btn-run-filtered').addEventListener('click', () => loadRunDetail(runId, 'filtered'));
        $('btn-run-raw').addEventListener('click', () => loadRunDetail(runId, 'raw'));
        $('btn-run-compare').addEventListener('click', () => loadRunDetail(runId, 'compare'));
        $('btn-run-copy-filtered').addEventListener('click', () => copyText(fd.content || ''));
        $('btn-run-copy-raw').addEventListener('click', () => copyText(rd.content || ''));
        return;
      }

      const env = await api(`/api/runs/${encodeURIComponent(runId)}?raw=${mode === 'raw' ? 'true' : 'false'}`);
      if (seq !== runDetailSeq) return;
      const d = env.data;
      const m = d.meta;
      $('run-detail').innerHTML = `
        ${renderRunHeaderAndTabs(m, mode)}
        <pre class="code-pre mt-md">${escHtml(d.content || emptyText)}</pre>`;
      $('btn-run-filtered').addEventListener('click', () => loadRunDetail(runId, 'filtered'));
      $('btn-run-raw').addEventListener('click', () => loadRunDetail(runId, 'raw'));
      $('btn-run-compare').addEventListener('click', () => loadRunDetail(runId, 'compare'));
      $('btn-run-copy').addEventListener('click', () => copyText(d.content || ''));
    } catch (err) {
      if (seq !== runDetailSeq) return;
      $('run-detail').innerHTML = `<p class="muted">${escHtml(err.message)}</p>`;
    }
  }

  // ==================== TAB 4: REAL STATS (100% API-UI FIELD PARITY) ====================
  async function loadStats() {
    const { state, $, escHtml, api } = core();
    try {
      const report = await api(`/api/stats?range=${encodeURIComponent(state.statsRange)}&scope=${encodeURIComponent(state.statsScope)}`);
      renderStats(report);
    } catch (err) {
      $('stats-content').innerHTML = `<div class="card"><p class="muted">${escHtml(err.message)}</p></div>`;
    }
  }

  function shortProjectName(raw) {
    const str = String(raw || '').trim();
    if (!str) return '-';
    const isEncodedPath =
      /^[A-Za-z]--/.test(str) || /^-(Users|home|var|opt|srv|mnt|Volumes)-/i.test(str);
    if (!isEncodedPath) return str;
    const anchorMatch = str.match(
      /^.*-(?:Desktop|Documents|Projects|Repos|Repositories|Workspaces?|GitHub|Dev|Code|Src)-(.+)$/i
    );
    if (anchorMatch && anchorMatch[1]) return anchorMatch[1];
    const homeMatch = str.match(/(?:^|-)(?:Users|home)-[^-]+-(.+)$/i);
    if (homeMatch && homeMatch[1]) return homeMatch[1];
    const parts = str.split('-').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : str;
  }

  function renderStats(report) {
    const { $, escHtml, fmtNum, t } = core();
    const schemaVersion = report.schema_version;
    const range = report.range;
    const projectFilter = report.project_filter;
    const hostConnected = Boolean(report.host_logs_connected);
    const hostSource = report.host_logs_source;
    const km = report.klens_metrics || {};
    const ht = report.host_totals;
    const byModel = report.by_model || [];
    const recentSessions = report.recent_sessions || [];

    $('stats-meta-label').textContent = `v${schemaVersion} · range=${range} · project=${projectFilter}${hostSource ? ` · host=${hostSource}` : ''}`;

    let html = `
      <h3 class="mt-sm">${escHtml(t('stats.layer1Title'))}</h3>
      <div class="kpi-grid mt-sm">
        <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.klensCalls'))}</div><div class="kpi-value">${fmtNum(km.klens_calls)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.tokensSaved'))}</div><div class="kpi-value">${fmtNum(km.estimated_tokens_saved)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.runsFiltered'))}</div><div class="kpi-value">${fmtNum(km.runs_filtered)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.staleCaught'))}</div><div class="kpi-value">${fmtNum(km.stale_memories_caught)}</div></div>
      </div>
      <h3 class="mt-lg">${escHtml(t('stats.layer2Title'))} ${hostSource ? `<span class="badge badge-blue">${escHtml(hostSource)}</span>` : ''}</h3>`;

    if (!hostConnected || !ht) {
      html += `<div class="card mt-sm"><p class="muted">${escHtml(t('stats.hostDisconnected'))}</p></div>`;
    } else {
      const freshIn = Number(ht.fresh_input_tokens || 0);
      const cacheTotal = Number(ht.cache_read_tokens || 0) + Number(ht.cache_creation_tokens || 0);
      const freshCacheLine = t('stats.freshVsCache')
        .replace('{fresh}', fmtNum(freshIn))
        .replace('{cache}', fmtNum(cacheTotal));
      html += `
        <div class="kpi-grid mt-sm">
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.sessionsCount'))}</div><div class="kpi-value">${fmtNum(ht.sessions_count)}</div></div>
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.inputTokens'))}</div><div class="kpi-value">${fmtNum(ht.total_input_tokens)}</div><div class="kpi-sub small muted mono">${escHtml(freshCacheLine)}</div></div>
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.outputTokens'))}</div><div class="kpi-value">${fmtNum(ht.total_output_tokens)}</div></div>
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.peakContext'))}</div><div class="kpi-value">${fmtNum(ht.peak_context_tokens)}</div></div>
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.bigReads'))}</div><div class="kpi-value">${fmtNum(ht.big_file_reads)}</div></div>
          <div class="kpi-card"><div class="kpi-label">${escHtml(t('stats.repeatedReads'))}</div><div class="kpi-value">${fmtNum(ht.repeated_overlapping_reads)}</div></div>
        </div>
        <div class="card mt-md">
          <div class="card-header"><h4>${escHtml(t('stats.byModel'))}</h4></div>
          <table class="data-table">
            <thead><tr><th>Model</th><th>Sessions</th><th>Tokens</th></tr></thead>
            <tbody>
              ${byModel.map((m) => `<tr><td class="mono">${escHtml(m.model)}</td><td class="mono">${fmtNum(m.sessions)}</td><td class="mono">${fmtNum(m.tokens)}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">No model records</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="card mt-md">
          <div class="card-header"><h4>${escHtml(t('stats.recentSessions'))} (${recentSessions.length})</h4></div>
          <table class="data-table">
            <thead><tr><th>Session</th><th>Project</th><th>Timestamp</th><th>Model</th><th>In / Out</th><th>Peak</th><th>Big / Re-read</th><th>klens</th></tr></thead>
            <tbody>
              ${recentSessions
                .map(
                  (s) => `
                <tr>
                  <td class="mono small">${escHtml(s.session_id)} ${s.is_subagent ? '<span class="badge">subagent</span>' : ''}</td>
                  <td title="${escHtml(s.project)}">${escHtml(shortProjectName(s.project))}</td>
                  <td class="mono small">${escHtml(s.timestamp_utc)}</td>
                  <td class="mono small">${escHtml(s.model || '-')}</td>
                  <td class="mono small">${fmtNum(s.input_tokens)} / ${fmtNum(s.output_tokens)}</td>
                  <td class="mono small">${fmtNum(s.peak_context_tokens)}</td>
                  <td class="mono small">${fmtNum(s.big_file_reads)} / ${fmtNum(s.repeated_overlapping_reads)}</td>
                  <td class="mono small">${fmtNum(s.klens_calls)}</td>
                </tr>`
                )
                .join('') || '<tr><td colspan="8" class="muted">No sessions</td></tr>'}
            </tbody>
          </table>
        </div>`;
    }

    $('stats-content').innerHTML = html;
  }

  window.KlensViews = Object.assign(window.KlensViews || {}, {
    loadMemoryList,
    openNewNoteModal,
    openExportMemoryModal,
    openRefreshAllModal,
    loadRunsList,
    loadStats,
  });
})();
