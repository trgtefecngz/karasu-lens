use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of elementary cycles reported before emitting an explicit omission.
const MAX_REPORTED_CYCLES: usize = 100;

/// Deterministic Tarjan SCC + canonical elementary cycle detection over a directed file graph.
pub(crate) fn detect_cycles_deterministic(
    adj: &BTreeMap<String, BTreeSet<String>>,
) -> (Vec<Vec<String>>, usize) {
    let mut all_nodes: BTreeSet<String> = BTreeSet::new();
    for (u, vs) in adj {
        all_nodes.insert(u.clone());
        for v in vs {
            all_nodes.insert(v.clone());
        }
    }

    let nodes: Vec<String> = all_nodes.into_iter().collect();
    let id_to_idx: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();
    let n = nodes.len();
    let mut int_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (u, vs) in adj {
        if let Some(&ui) = id_to_idx.get(u.as_str()) {
            for v in vs {
                if let Some(&vi) = id_to_idx.get(v.as_str()) {
                    int_adj[ui].push(vi);
                }
            }
            int_adj[ui].sort_unstable();
            int_adj[ui].dedup();
        }
    }

    let sccs = tarjan_scc(&int_adj);
    let mut canonical_cycles: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut overflow_count = 0usize;

    for mut scc in sccs {
        scc.sort_unstable();
        if scc.len() == 1 {
            let u = scc[0];
            if int_adj[u].contains(&u) {
                let cyc = vec![nodes[u].clone(), nodes[u].clone()];
                if canonical_cycles.len() < MAX_REPORTED_CYCLES {
                    canonical_cycles.insert(cyc);
                } else {
                    overflow_count += 1;
                }
            }
            continue;
        }

        let scc_set: BTreeSet<usize> = scc.iter().copied().collect();
        for &start in &scc {
            let mut path = vec![start];
            let mut on_path: BTreeSet<usize> = BTreeSet::new();
            on_path.insert(start);

            dfs_cycles_from_start(
                start,
                start,
                &int_adj,
                &scc_set,
                &nodes,
                &mut path,
                &mut on_path,
                &mut canonical_cycles,
                &mut overflow_count,
            );
        }
    }

    (canonical_cycles.into_iter().collect(), overflow_count)
}

#[allow(clippy::too_many_arguments)]
fn dfs_cycles_from_start(
    start: usize,
    current: usize,
    adj: &[Vec<usize>],
    scc_set: &BTreeSet<usize>,
    nodes: &[String],
    path: &mut Vec<usize>,
    on_path: &mut BTreeSet<usize>,
    cycles: &mut BTreeSet<Vec<String>>,
    overflow_count: &mut usize,
) {
    const MAX_CYCLE_LEN: usize = 12;
    if path.len() > MAX_CYCLE_LEN || *overflow_count >= 256 {
        return;
    }

    for &next in &adj[current] {
        if !scc_set.contains(&next) || next < start {
            continue;
        }
        if next == start {
            let mut cyc: Vec<String> = path.iter().map(|&idx| nodes[idx].clone()).collect();
            cyc.push(nodes[start].clone());
            if cycles.len() < MAX_REPORTED_CYCLES {
                cycles.insert(cyc);
            } else {
                *overflow_count += 1;
            }
        } else if !on_path.contains(&next) {
            on_path.insert(next);
            path.push(next);
            dfs_cycles_from_start(
                start,
                next,
                adj,
                scc_set,
                nodes,
                path,
                on_path,
                cycles,
                overflow_count,
            );
            path.pop();
            on_path.remove(&next);
        }
    }
}

fn tarjan_scc(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct State {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    fn strongconnect(v: usize, adj: &[Vec<usize>], st: &mut State) {
        st.indices[v] = Some(st.index);
        st.lowlink[v] = st.index;
        st.index += 1;
        st.stack.push(v);
        st.on_stack[v] = true;

        for &w in &adj[v] {
            if st.indices[w].is_none() {
                strongconnect(w, adj, st);
                st.lowlink[v] = st.lowlink[v].min(st.lowlink[w]);
            } else if st.on_stack[w] {
                st.lowlink[v] = st.lowlink[v].min(st.indices[w].unwrap_or(usize::MAX));
            }
        }

        if st.lowlink[v] == st.indices[v].unwrap_or(usize::MAX) {
            let mut comp = Vec::new();
            while let Some(w) = st.stack.pop() {
                st.on_stack[w] = false;
                comp.push(w);
                if w == v {
                    break;
                }
            }
            st.sccs.push(comp);
        }
    }

    let n = adj.len();
    let mut st = State {
        index: 0,
        indices: vec![None; n],
        lowlink: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    for v in 0..n {
        if st.indices[v].is_none() {
            strongconnect(v, adj, &mut st);
        }
    }

    st.sccs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_cycles_finds_two_node_cycle_canonically() {
        let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        adj.entry("file:src/a.rs".into())
            .or_default()
            .insert("file:src/b.rs".into());
        adj.entry("file:src/b.rs".into())
            .or_default()
            .insert("file:src/a.rs".into());
        let (cycles, overflow) = detect_cycles_deterministic(&adj);
        assert_eq!(overflow, 0);
        assert_eq!(
            cycles,
            vec![vec![
                "file:src/a.rs".to_string(),
                "file:src/b.rs".to_string(),
                "file:src/a.rs".to_string(),
            ]]
        );
    }
}
