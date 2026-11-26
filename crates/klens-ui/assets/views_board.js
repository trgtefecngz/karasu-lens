(() => {
  'use strict';

  function core() {
    return window.KlensCore;
  }

  // ==================== TAB 1: BLUEPRINT ====================
  async function loadBlueprint(forceRender) {
    const { state, $, escHtml, api } = core();
    if (!forceRender) {
      const active = document.activeElement;
      const bpRoot = $('bp-content');
      if (
        active &&
        bpRoot &&
        bpRoot.contains(active) &&
        (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')
      ) {
        return;
      }
    }
    try {
      const data = await api('/api/blueprint');
      const key = JSON.stringify({
        bp: data.blueprint,
        tasks: data.tasks,
        status: data.status?.data,
        ro: data.read_only,
        lang: state.lang,
      });
      if (!forceRender && key === state.bpSnapshotKey) return;
      state.bpSnapshotKey = key;
      renderBlueprint(data);
    } catch (err) {
      $('bp-content').innerHTML = `<div class="card"><p class="muted">${escHtml(err.message)}</p></div>`;
    }
  }

  function renderBlueprint(data) {
    const { state, $, escHtml, t, toast, copyText, api } = core();
    const bp = data.blueprint;
    const status = data.status?.data || {};
    const tasks = data.tasks || [];
    const ro = !!data.read_only;

    const stepState = !bp ? 1 : status.locked ? 4 : status.conflicts?.error_count > 0 ? 3 : status.pending_bubbles > 0 ? 2 : 4;
    document.querySelectorAll('#bp-steps .step-pill').forEach((el) => {
      const n = Number(el.dataset.step);
      el.classList.toggle('done', n < stepState || (status.locked && n === 4));
      el.classList.toggle('current', n === stepState && !status.locked);
    });

    const host = $('bp-content');
    if (!bp) {
      host.innerHTML = `
        <div class="card">
          <div class="card-header"><h3>${escHtml(t('bp.emptyTitle'))}</h3></div>
          <p class="muted">${escHtml(t('bp.emptyBody'))}</p>
          <div class="row gap-sm mt-md">
            <input id="bp-init-name" class="input" placeholder="${escHtml(t('bp.projectName'))}" value="${escHtml(state.status?.active_project?.name || '')}" />
            <input id="bp-init-goal" class="input" style="flex:1" placeholder="${escHtml(t('bp.goal'))}" />
            <button id="btn-bp-create" class="btn btn-primary" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('bp.startBtn'))}</button>
          </div>
        </div>`;
      $('btn-bp-create')?.addEventListener('click', async () => {
        const name = $('bp-init-name').value.trim();
        const goal = $('bp-init-goal').value.trim() || 'Build cleanly with verified architecture';
        if (!name) return toast('Project name is required', 'error');
        try {
          await api('/api/blueprint/propose', {
            method: 'POST',
            body: {
              project_name: name,
              goal,
              bubbles: [
                {
                  id: 'platform',
                  category: 'Platform',
                  title: 'Where will this project run?',
                  plain_explanation: 'Determines language runtime, packaging, and local filesystem access.',
                  options: [
                    { id: 'desktop', label: 'Desktop / CLI', pros: 'Direct local performance', cons: 'Requires install', recommended: true, provides: ['local_fs'], requires: [], conflicts_with: [] },
                    { id: 'web', label: 'Web Application', pros: 'Instant URL sharing', cons: 'Browser sandbox limits', recommended: false, provides: ['browser'], requires: [], conflicts_with: [] },
                  ],
                  selected_option: null,
                  user_vision_note: '',
                  status: 'pending',
                  depends_on: [],
                },
              ],
            },
          });
          state.bpSnapshotKey = '';
          loadBlueprint(true);
        } catch (err) { toast(err.message, 'error'); }
      });
      return;
    }

    const conflicts = status.conflicts?.conflicts || [];
    const errorCount = status.conflicts?.error_count || 0;
    const canLock = !!status.conflicts?.can_lock && !ro;
    const conflictBubbleSet = new Set();
    conflicts.forEach((c) => (c.bubble_ids || []).forEach((id) => conflictBubbleSet.add(id)));

    let html = `
      <div class="card">
        <div class="card-header">
          <div>
            <h3>${escHtml(bp.project_name)} ${bp.locked ? `<span class="badge badge-green">${escHtml(t('bp.lockedBadge'))}</span>` : ''}</h3>
            <div class="muted small">${escHtml(bp.goal)}</div>
          </div>
          <div class="row gap-sm">
            <label class="row gap-sm small muted">
              <input id="bp-scaffold-chk" type="checkbox" ${ro ? 'disabled' : ''} />
              ${escHtml(t('bp.scaffoldLabel'))}
            </label>
            <button id="btn-bp-lock" class="btn btn-primary" type="button" ${canLock ? '' : 'disabled'}>${escHtml(t('bp.lockBtn'))}</button>
          </div>
        </div>
      </div>`;

    html += conflicts.length
      ? `<div class="conflict-banner mt-md">
           <strong>${escHtml(t('bp.conflictsTitle'))} (${errorCount} error / ${status.conflicts?.warning_count || 0} warning)</strong>
           <ul class="mt-sm small">${conflicts.map((c) => `<li><span class="badge ${c.severity === 'error' ? 'badge-red' : 'badge-amber'}">${escHtml(c.severity)}</span> ${escHtml(c.message)}</li>`).join('')}</ul>
         </div>`
      : `<div class="conflict-banner ok mt-md"><strong>${escHtml(t('bp.noConflicts'))}</strong></div>`;

    html += `<div class="bubble-grid mt-md">`;
    for (const b of bp.bubbles || []) {
      const hasConflict = conflictBubbleSet.has(b.id);
      const stBadge = hasConflict
        ? `<span class="badge badge-red">${escHtml(t('bp.statusConflict'))}</span>`
        : b.status === 'user_confirmed'
          ? `<span class="badge badge-green">${escHtml(t('bp.statusConfirmed'))}</span>`
          : `<span class="badge badge-amber">${escHtml(t('bp.statusPending'))}</span>`;
      html += `
        <div class="card" data-bubble="${escHtml(b.id)}">
          <div class="card-header">
            <div><span class="badge badge-blue">${escHtml(b.category)}</span><h4 class="mt-sm">${escHtml(b.title)}</h4></div>
            ${stBadge}
          </div>
          <p class="muted small">${escHtml(b.plain_explanation)}</p>
          <div class="mt-sm">
            ${(b.options || [])
              .map(
                (o) => `
              <div class="option-card ${b.selected_option === o.id ? 'selected' : ''}" data-bubble-opt="${escHtml(b.id)}" data-opt-id="${escHtml(o.id)}">
                <div class="row"><strong>${escHtml(o.label)}</strong>${o.recommended ? `<span class="badge badge-green" style="margin-left:6px">${escHtml(t('bp.recommended'))}</span>` : ''}</div>
                ${o.pros ? `<div class="small muted">+ ${escHtml(t('bp.pros'))}: ${escHtml(o.pros)}</div>` : ''}
                ${o.cons ? `<div class="small muted">- ${escHtml(t('bp.cons'))}: ${escHtml(o.cons)}</div>` : ''}
              </div>`
              )
              .join('')}
          </div>
          <div class="mt-sm">
            <label class="small muted">${escHtml(t('bp.visionNote'))}</label>
            <textarea class="textarea mt-sm" data-vision="${escHtml(b.id)}" placeholder="${escHtml(t('bp.visionPlaceholder'))}" ${ro ? 'disabled' : ''}>${escHtml(b.user_vision_note || '')}</textarea>
          </div>
          <div class="row mt-sm"><span class="spacer"></span><button class="btn btn-primary" data-confirm-bubble="${escHtml(b.id)}" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('bp.saveSelection'))}</button></div>
        </div>`;
    }
    html += `</div>`;

    if (tasks.length) {
      html += `
        <div class="card mt-lg">
          <div class="card-header"><h3>${escHtml(t('bp.tasksTitle'))} (${status.done_tasks || 0}/${tasks.length})</h3></div>
          <div class="list-stack">
            ${tasks
              .map(
                (tk) => `
              <div class="list-item">
                <div><span class="mono small">${escHtml(tk.id)}</span> <strong style="margin-left:8px">${escHtml(tk.title)}</strong>${tk.blocked_by?.length ? `<span class="muted small"> (blocked_by: ${escHtml(tk.blocked_by.join(', '))})</span>` : ''}</div>
                <div class="row gap-sm">
                  <span class="badge ${tk.status === 'done' ? 'badge-green' : 'badge-amber'}">${escHtml(tk.status)}</span>
                  ${tk.status !== 'done' && !ro ? `<button class="btn btn-ghost small" data-complete-task="${escHtml(tk.id)}" type="button">${escHtml(t('bp.completeTask'))}</button>` : ''}
                </div>
              </div>`
              )
              .join('')}
          </div>
        </div>`;
    }

    if (data.contract_markdown) {
      html += `
        <div class="card mt-lg">
          <div class="card-header"><h3>${escHtml(t('bp.contractTitle'))}</h3><button id="btn-copy-contract" class="btn btn-ghost" type="button">${escHtml(t('bp.copyContract'))}</button></div>
          <pre class="code-pre">${escHtml(data.contract_markdown)}</pre>
        </div>`;
    }

    host.innerHTML = html;

    host.querySelectorAll('[data-bubble-opt]').forEach((el) =>
      el.addEventListener('click', () => {
        if (ro) return;
        const bid = el.dataset.bubbleOpt;
        host.querySelectorAll(`[data-bubble-opt="${CSS.escape(bid)}"]`).forEach((o) => o.classList.remove('selected'));
        el.classList.add('selected');
      })
    );
    host.querySelectorAll('[data-confirm-bubble]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        const bid = btn.dataset.confirmBubble;
        const selectedEl = host.querySelector(`[data-bubble-opt="${CSS.escape(bid)}"].selected`);
        if (!selectedEl) return toast('Select an option first', 'error');
        const noteEl = host.querySelector(`[data-vision="${CSS.escape(bid)}"]`);
        try {
          await api('/api/blueprint/select', {
            method: 'POST',
            body: { bubble_id: bid, option_id: selectedEl.dataset.optId, vision_note: noteEl ? noteEl.value : '', confirm: true },
          });
          state.bpSnapshotKey = '';
          loadBlueprint(true);
        } catch (err) { toast(err.message, 'error'); }
      })
    );
    $('btn-bp-lock')?.addEventListener('click', async () => {
      try {
        const scaffold = $('bp-scaffold-chk')?.checked || false;
        await api('/api/blueprint/lock', { method: 'POST', body: { create_scaffold: scaffold } });
        toast('Blueprint locked — PROJECT_CONTRACT.md & tasks.jsonl generated.', 'ok');
        state.bpSnapshotKey = '';
        loadBlueprint(true);
      } catch (err) { toast(err.message, 'error'); }
    });
    host.querySelectorAll('[data-complete-task]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        try {
          await api('/api/blueprint/tasks/complete', { method: 'POST', body: { task_id: btn.dataset.completeTask } });
          state.bpSnapshotKey = '';
          loadBlueprint(true);
        } catch (err) { toast(err.message, 'error'); }
      })
    );
    $('btn-copy-contract')?.addEventListener('click', () => copyText(data.contract_markdown));
  }

  // ==================== TAB 2: CODE & MEMORY MAP ====================
  const graphView = {
    x: 0,
    y: 0,
    scale: 1,
    minScale: 0.25,
    maxScale: 2.5,
    bounds: { minX: 0, minY: 0, maxX: 760, maxY: 460 },
    projectKey: '',
    initialized: false,
    bound: false,
    suppressClick: false,
  };

  function getGraphWrap() {
    return document.querySelector('#tab-code .graph-canvas-wrap');
  }

  function applyGraphTransform() {
    const vp = core().$('graph-viewport');
    if (vp) {
      vp.setAttribute(
        'transform',
        `translate(${graphView.x.toFixed(2)}, ${graphView.y.toFixed(2)}) scale(${graphView.scale.toFixed(4)})`
      );
    }
    const resetBtn = core().$('btn-graph-zoom-reset');
    if (resetBtn) resetBtn.textContent = `${Math.round(graphView.scale * 100)}%`;
  }

  function zoomGraphAt(targetScale, cx, cy) {
    const nextScale = Math.max(graphView.minScale, Math.min(graphView.maxScale, targetScale));
    const wx = (cx - graphView.x) / graphView.scale;
    const wy = (cy - graphView.y) / graphView.scale;
    graphView.scale = nextScale;
    graphView.x = cx - wx * nextScale;
    graphView.y = cy - wy * nextScale;
    applyGraphTransform();
  }

  function zoomGraphByFactor(factor) {
    const wrap = getGraphWrap();
    const rect = wrap ? wrap.getBoundingClientRect() : null;
    const cx = rect && rect.width > 0 ? rect.width / 2 : 380;
    const cy = rect && rect.height > 0 ? rect.height / 2 : 260;
    zoomGraphAt(graphView.scale * factor, cx, cy);
  }

  function resetGraphZoom() {
    graphView.scale = 1;
    graphView.x = 0;
    graphView.y = 0;
    applyGraphTransform();
  }

  function fitGraphToView() {
    const wrap = getGraphWrap();
    const rect = wrap ? wrap.getBoundingClientRect() : null;
    const vw = rect && rect.width > 40 ? rect.width : 760;
    const vh = rect && rect.height > 40 ? rect.height : 520;
    const b = graphView.bounds;
    const bw = Math.max(120, b.maxX - b.minX);
    const bh = Math.max(120, b.maxY - b.minY);
    const pad = 24;
    const rawScale = Math.min((vw - pad * 2) / bw, (vh - pad * 2) / bh, 1.25);
    const scale = Math.max(graphView.minScale, Math.min(graphView.maxScale, rawScale));
    graphView.scale = scale;
    graphView.x = (vw - bw * scale) / 2 - b.minX * scale;
    graphView.y = (vh - bh * scale) / 2 - b.minY * scale;
    applyGraphTransform();
  }

  function ensureGraphPanZoomBound() {
    if (graphView.bound) return;
    const { $ } = core();
    const wrap = getGraphWrap();
    if (!wrap) return;

    $('btn-graph-zoom-out')?.addEventListener('click', () => zoomGraphByFactor(1 / 1.25));
    $('btn-graph-zoom-in')?.addEventListener('click', () => zoomGraphByFactor(1.25));
    $('btn-graph-zoom-reset')?.addEventListener('click', resetGraphZoom);
    $('btn-graph-fit')?.addEventListener('click', fitGraphToView);

    wrap.addEventListener(
      'wheel',
      (ev) => {
        ev.preventDefault();
        const rect = wrap.getBoundingClientRect();
        const mx = ev.clientX - rect.left;
        const my = ev.clientY - rect.top;
        const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
        zoomGraphAt(graphView.scale * factor, mx, my);
      },
      { passive: false }
    );

    let dragging = false;
    let didDrag = false;
    let startX = 0;
    let startY = 0;
    let origX = 0;
    let origY = 0;

    wrap.addEventListener('mousedown', (ev) => {
      if (ev.button !== 0) return;
      dragging = true;
      didDrag = false;
      startX = ev.clientX;
      startY = ev.clientY;
      origX = graphView.x;
      origY = graphView.y;
    });

    window.addEventListener('mousemove', (ev) => {
      if (!dragging) return;
      const dx = ev.clientX - startX;
      const dy = ev.clientY - startY;
      if (!didDrag && Math.hypot(dx, dy) > 4) {
        didDrag = true;
        wrap.classList.add('is-panning');
      }
      if (didDrag) {
        graphView.x = origX + dx;
        graphView.y = origY + dy;
        applyGraphTransform();
      }
    });

    window.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      wrap.classList.remove('is-panning');
      if (didDrag) {
        graphView.suppressClick = true;
        setTimeout(() => {
          graphView.suppressClick = false;
        }, 0);
      }
    });

    graphView.bound = true;
  }

  function updateSelectedGraphNode(relPath) {
    const svg = core().$('code-graph-svg');
    if (!svg) return;
    svg.querySelectorAll('.graph-node').forEach((nodeEl) => {
      nodeEl.classList.toggle('selected', nodeEl.dataset.nodePath === relPath);
    });
  }

  async function loadCodeGraph() {
    const { state, $, api } = core();
    try {
      state.graphData = await api('/api/code/graph');
      renderCodeGraph();
    } catch (err) {
      $('graph-summary').textContent = err.message;
    }
  }

  function renderCodeGraph() {
    ensureGraphPanZoomBound();
    const { state, $, escHtml, t } = core();
    const payload = state.graphData;
    if (!payload) return;
    const graph = payload.graph?.data || { nodes: [], edges: [], cycles: [], clusters: {}, god_nodes: [] };
    const staleSet = new Set(payload.stale_files || []);
    const failedSet = new Set(payload.failed_run_files || []);
    const memBadges = payload.memory_badges || {};
    const filter = ($('code-filter')?.value || '').trim().toLowerCase();

    $('graph-summary').textContent = `${graph.nodes.length} files · ${graph.edges.length} edges · ${graph.god_nodes.length} God Nodes · ${graph.cycles.length} cycles`;

    const clusters = Object.keys(graph.clusters || {}).sort();
    const bar = $('graph-clusters-bar');
    bar.innerHTML = clusters
      .map((cl) => {
        const count = (graph.clusters[cl] || []).length;
        const collapsed = state.collapsedClusters.has(cl);
        return `<button class="pill ${collapsed ? '' : 'active'}" data-cluster="${escHtml(cl)}" type="button">${escHtml(cl)} (${count})</button>`;
      })
      .join('');
    bar.querySelectorAll('[data-cluster]').forEach((btn) =>
      btn.addEventListener('click', () => {
        const cl = btn.dataset.cluster;
        if (state.collapsedClusters.has(cl)) state.collapsedClusters.delete(cl);
        else state.collapsedClusters.add(cl);
        renderCodeGraph();
      })
    );

    const visibleNodes = graph.nodes.filter((n) => {
      if (state.collapsedClusters.has(n.cluster)) return false;
      if (!filter) return true;
      return n.path.toLowerCase().includes(filter) || n.cluster.toLowerCase().includes(filter);
    });

    const byCluster = new Map();
    for (const n of visibleNodes) {
      if (!byCluster.has(n.cluster)) byCluster.set(n.cluster, []);
      byCluster.get(n.cluster).push(n);
    }

    const colW = 280;
    const nodeW = 232;
    const nodeH = 42;
    const gapY = 14;
    const padX = 20;
    const padY = 40;
    const pos = new Map();
    let maxRows = 1;
    let colIdx = 0;

    for (const [cl, nodes] of byCluster.entries()) {
      maxRows = Math.max(maxRows, nodes.length);
      nodes.forEach((n, rowIdx) => {
        pos.set(n.id, { x: padX + colIdx * colW, y: padY + rowIdx * (nodeH + gapY), node: n, cluster: cl });
      });
      colIdx++;
    }

    const contentMaxX = colIdx > 0 ? padX + (colIdx - 1) * colW + nodeW : 760;
    const contentMaxY = padY + Math.max(1, maxRows) * (nodeH + gapY) + 16;
    graphView.bounds = { minX: padX, minY: 8, maxX: contentMaxX, maxY: contentMaxY };

    const cycleNodes = new Set();
    (graph.cycles || []).forEach((c) => c.forEach((id) => cycleNodes.add(id)));

    const svg = $('code-graph-svg');
    svg.removeAttribute('width');
    svg.removeAttribute('height');
    svg.removeAttribute('viewBox');

    let viewportHtml = '';
    let cIdx = 0;
    for (const cl of byCluster.keys()) {
      viewportHtml += `<text x="${padX + cIdx * colW}" y="22" fill="var(--text-secondary)" font-size="11" font-family="var(--font-mono)">${escHtml(cl)}</text>`;
      cIdx++;
    }

    const drawnEdges = new Set();
    for (const e of graph.edges || []) {
      const fromId = e.from.startsWith('file:') ? e.from : `file:${e.from.replace(/^sym:/, '').split('#')[0]}`;
      const toId = e.to.startsWith('file:') ? e.to : `file:${e.to.replace(/^sym:/, '').split('#')[0]}`;
      const p1 = pos.get(fromId);
      const p2 = pos.get(toId);
      if (!p1 || !p2 || fromId === toId) continue;
      const edgeKey = `${fromId}->${toId}:${e.confidence}`;
      if (drawnEdges.has(edgeKey)) continue;
      drawnEdges.add(edgeKey);

      const x1 = p1.x + nodeW;
      const y1 = p1.y + nodeH / 2;
      const x2 = p2.x;
      const y2 = p2.y + nodeH / 2;
      const mx = (x1 + x2) / 2;
      const conf = String(e.confidence || '').toUpperCase();
      const dash = conf === 'INFERRED' ? 'stroke-dasharray="6,4"' : conf === 'AMBIGUOUS' ? 'stroke-dasharray="2,3"' : '';
      const color = conf === 'EXTRACTED' ? 'var(--accent)' : conf === 'AMBIGUOUS' ? 'var(--amber)' : 'var(--text-muted)';
      viewportHtml += `<path class="graph-edge" data-from="${escHtml(p1.node.path)}" data-to="${escHtml(p2.node.path)}" d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}" fill="none" stroke="${color}" stroke-opacity="0.55" stroke-width="1.3" ${dash} />`;
    }

    for (const [, p] of pos.entries()) {
      const n = p.node;
      const cls = `graph-node${state.selectedNodePath === n.path ? ' selected' : ''}${n.is_god_node ? ' god' : ''}`;
      const isStale = staleSet.has(n.path);
      const isFailed = failedSet.has(n.path);
      const isCycle = cycleNodes.has(n.id);
      const memCount = memBadges[n.path]?.total_notes || 0;
      const hasTopDots = n.is_god_node || isStale || isFailed;
      const maxLabelLen = hasTopDots ? 24 : 29;
      const shortLabel = n.label.length > maxLabelLen ? `${n.label.slice(0, maxLabelLen - 2)}..` : n.label;
      const titleClip = hasTopDots ? 'url(#graph-clip-dots)' : 'url(#graph-clip-full)';
      const metaClip = isCycle ? 'url(#graph-clip-cycle)' : memCount > 0 ? 'url(#graph-clip-mem)' : 'url(#graph-clip-full)';
      const metaText = `${n.lines}L · ${n.symbol_count} sym · in:${n.in_degree} out:${n.out_degree}`;
      viewportHtml += `
        <g class="${cls}" data-node-path="${escHtml(n.path)}" transform="translate(${p.x},${p.y})">
          <title>${escHtml(n.path)}</title>
          <rect width="${nodeW}" height="${nodeH}" />
          <g clip-path="${titleClip}">
            <text x="10" y="18">${escHtml(shortLabel)}</text>
          </g>
          <g clip-path="${metaClip}">
            <text x="10" y="33" fill="var(--text-muted)" font-size="10">${escHtml(metaText)}</text>
          </g>
          ${n.is_god_node ? `<circle cx="${nodeW - 12}" cy="12" r="4" fill="var(--amber)"><title>${escHtml(t('code.godNode'))}</title></circle>` : ''}
          ${isStale ? `<circle cx="${nodeW - 24}" cy="12" r="4" fill="var(--red)"><title>${escHtml(t('code.staleBadge'))}</title></circle>` : ''}
          ${isFailed ? `<circle cx="${nodeW - 36}" cy="12" r="4" fill="var(--red)"><title>${escHtml(t('code.failedRun'))}</title></circle>` : ''}
          ${isCycle ? `<rect x="${nodeW - 50}" y="26" width="42" height="12" rx="3" fill="var(--red-soft)" stroke="none"></rect><text x="${nodeW - 46}" y="35" fill="var(--red)" font-size="9">CYCLE</text>` : ''}
          ${memCount > 0 && !isCycle ? `<text x="${nodeW - 32}" y="35" fill="var(--green)" font-size="9">M:${memCount}</text>` : ''}
        </g>`;
    }

    const defsHtml = `
      <defs>
        <clipPath id="graph-clip-full"><rect x="6" y="0" width="${nodeW - 14}" height="${nodeH}" /></clipPath>
        <clipPath id="graph-clip-dots"><rect x="6" y="0" width="${nodeW - 48}" height="24" /></clipPath>
        <clipPath id="graph-clip-cycle"><rect x="6" y="20" width="${nodeW - 58}" height="22" /></clipPath>
        <clipPath id="graph-clip-mem"><rect x="6" y="20" width="${nodeW - 40}" height="22" /></clipPath>
      </defs>`;

    svg.innerHTML = `${defsHtml}<g id="graph-viewport">${viewportHtml}</g>`;

    const curProjectKey = state.status?.active_project?.path || '';
    if (!graphView.initialized || graphView.projectKey !== curProjectKey) {
      graphView.projectKey = curProjectKey;
      graphView.initialized = true;
      fitGraphToView();
    } else {
      applyGraphTransform();
    }

    svg.querySelectorAll('[data-node-path]').forEach((g) => {
      g.addEventListener('click', () => {
        if (graphView.suppressClick) return;
        inspectNode(g.dataset.nodePath);
      });
      g.addEventListener('mouseenter', () => {
        const hovered = g.dataset.nodePath;
        svg.querySelectorAll('.graph-edge').forEach((edge) => {
          const connected = edge.dataset.from === hovered || edge.dataset.to === hovered;
          edge.classList.toggle('edge-highlight', connected);
          edge.classList.toggle('edge-dim', !connected);
        });
      });
      g.addEventListener('mouseleave', () => {
        svg.querySelectorAll('.graph-edge').forEach((edge) => {
          edge.classList.remove('edge-highlight', 'edge-dim');
        });
      });
    });
  }

  async function inspectNode(relPath) {
    const { state, $, escHtml, t, toast, api } = core();
    state.selectedNodePath = relPath;
    updateSelectedGraphNode(relPath);
    const body = $('node-inspector-body');
    body.innerHTML = `<div class="mono small">${escHtml(relPath)}</div><p class="muted small">Loading AST outline &amp; impact...</p>`;

    const ro = !!state.status?.read_only;
    const memBadge = state.graphData?.memory_badges?.[relPath];

    let outlineHtml = '';
    let impactHtml = '';
    try {
      const [outEnv, impEnv] = await Promise.all([
        api(`/api/code/outline?path=${encodeURIComponent(relPath)}`),
        api(`/api/code/impact?target=${encodeURIComponent(relPath)}`),
      ]);
      const syms = outEnv.data?.files?.[0]?.symbols || [];
      outlineHtml = syms.length
        ? syms.map((s) => `<div class="mono small">L${s.start_line}-${s.end_line} <strong>${escHtml(s.qualified_name || s.name)}</strong> <span class="muted">${escHtml(s.kind)}</span></div>`).join('')
        : `<p class="muted small">No AST symbols extracted.</p>`;

      const hits = impEnv.data?.hits || [];
      impactHtml = hits.length
        ? hits.slice(0, 20).map((h) => `<div class="mono small"><span class="badge">${escHtml(h.confidence)}</span> ${escHtml(h.path)}${h.line ? `:${h.line}` : ''} (${escHtml(h.relation)})</div>`).join('')
        : `<p class="muted small">0 incoming dependents found.</p>`;
    } catch (err) {
      outlineHtml = `<p class="muted small">${escHtml(err.message)}</p>`;
    }

    const memIds = memBadge?.note_ids || [];
    const memHtml = memIds.length
      ? memIds.map((id) => `<span class="badge badge-blue mono">${escHtml(id)}</span>`).join(' ')
      : `<span class="muted small">None</span>`;

    body.innerHTML = `
      <div>
        <div class="mono"><strong>${escHtml(relPath)}</strong></div>
        <div class="row gap-sm mt-sm">${memBadge?.stale_notes ? `<span class="badge badge-red">${escHtml(t('code.staleBadge'))}: ${memBadge.stale_notes}</span>` : ''}</div>
      </div>
      <div><h4>${escHtml(t('code.outline'))}</h4><div class="list-stack mt-sm" style="max-height:160px;overflow:auto">${outlineHtml}</div></div>
      <div><h4>${escHtml(t('code.impact'))}</h4><div class="list-stack mt-sm" style="max-height:130px;overflow:auto">${impactHtml}</div></div>
      <div><h4>${escHtml(t('code.linkedMemory'))}</h4><div class="row gap-sm mt-sm">${memHtml}</div></div>
      <div class="card" style="background:var(--bg-elevated)">
        <h4>${escHtml(t('code.leaveFeedback'))}</h4>
        <input id="fb-title" class="input mt-sm" style="width:100%" placeholder="${escHtml(t('code.feedbackTitle'))}" ${ro ? 'disabled' : ''} />
        <textarea id="fb-body" class="textarea mt-sm" placeholder="${escHtml(t('code.feedbackBody'))}" ${ro ? 'disabled' : ''}></textarea>
        <button id="btn-fb-save" class="btn btn-primary mt-sm" type="button" ${ro ? 'disabled' : ''}>${escHtml(t('code.feedbackSubmit'))}</button>
      </div>`;

    $('btn-fb-save')?.addEventListener('click', async () => {
      const title = $('fb-title').value.trim();
      const fbBody = $('fb-body').value.trim();
      if (!title) return toast('Title is required', 'error');
      try {
        await api('/api/memory', {
          method: 'POST',
          body: { title, kind: 'feedback', body: fbBody, anchors: [relPath], tags: ['feedback', 'ui'] },
        });
        toast('Feedback note saved to .klens/memory/.', 'ok');
        loadCodeGraph();
        inspectNode(relPath);
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  window.KlensViews = Object.assign(window.KlensViews || {}, {
    loadBlueprint,
    loadCodeGraph,
    renderCodeGraph,
  });
})();
