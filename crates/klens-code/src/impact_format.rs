//! Compact text rendering of impact hits for agents.
//!
//! The raw hit list can reach thousands of lines (every reference along a transitive import
//! chain). Agents need the closest, most certain dependents first, one line per file. The JSON
//! form keeps every hit; this text form groups and caps, and always says what it left out.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use klens_core::EdgeConfidence;

use crate::impact::ImpactHit;

/// Files listed in the text form before the rest is summarised.
pub const MAX_TEXT_FILES: usize = 30;
/// Line references listed per file before `+N more`.
pub const MAX_LINES_PER_FILE: usize = 6;

fn confidence_rank(confidence: EdgeConfidence) -> u8 {
    match confidence {
        EdgeConfidence::VerifiedLsp => 0,
        EdgeConfidence::Extracted => 1,
        EdgeConfidence::Inferred => 2,
        EdgeConfidence::Ambiguous => 3,
    }
}

struct FileGroup<'a> {
    path: &'a str,
    distance: usize,
    confidence: EdgeConfidence,
    relations: Vec<String>,
    refs: Vec<String>,
    hits: usize,
}

/// One line per affected file, closest and most certain first, capped with an explicit footer.
pub(crate) fn write_grouped_hits(out: &mut String, hits: &[ImpactHit]) {
    let mut groups: BTreeMap<&str, FileGroup<'_>> = BTreeMap::new();
    for hit in hits {
        let group = groups
            .entry(hit.path.as_str())
            .or_insert_with(|| FileGroup {
                path: hit.path.as_str(),
                distance: hit.distance,
                confidence: hit.confidence,
                relations: Vec::new(),
                refs: Vec::new(),
                hits: 0,
            });
        group.hits += 1;
        // The confidence shown belongs to the closest hits, never to a farther, more certain one.
        if hit.distance < group.distance {
            group.distance = hit.distance;
            group.confidence = hit.confidence;
        } else if hit.distance == group.distance
            && confidence_rank(hit.confidence) < confidence_rank(group.confidence)
        {
            group.confidence = hit.confidence;
        }
        let relation = format!("{:?}", hit.relation);
        if !group.relations.contains(&relation) {
            group.relations.push(relation);
        }
        if let Some(line) = hit.line {
            let reference = match &hit.enclosing_symbol {
                Some(symbol) => format!("L{line} in `{symbol}`"),
                None => format!("L{line}"),
            };
            if !group.refs.contains(&reference) {
                group.refs.push(reference);
            }
        }
    }

    let mut ordered: Vec<FileGroup<'_>> = groups.into_values().collect();
    ordered.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then(confidence_rank(a.confidence).cmp(&confidence_rank(b.confidence)))
            .then(a.path.cmp(b.path))
    });

    for group in ordered.iter().take(MAX_TEXT_FILES) {
        let shown: Vec<&str> = group
            .refs
            .iter()
            .take(MAX_LINES_PER_FILE)
            .map(String::as_str)
            .collect();
        let mut refs = shown.join(", ");
        if group.refs.len() > MAX_LINES_PER_FILE {
            let _ = write!(refs, ", +{} more", group.refs.len() - MAX_LINES_PER_FILE);
        }
        let separator = if refs.is_empty() { "" } else { ": " };
        let _ = writeln!(
            out,
            "  [d={} | {:?} | {}] {}{separator}{refs}",
            group.distance,
            group.confidence,
            group.relations.join("+"),
            group.path
        );
    }

    if ordered.len() > MAX_TEXT_FILES {
        let rest = &ordered[MAX_TEXT_FILES..];
        let rest_hits: usize = rest.iter().map(|g| g.hits).sum();
        let deep = rest.iter().filter(|g| g.distance >= 3).count();
        let _ = writeln!(
            out,
            "  ... omitted {} more files ({rest_hits} hits; {deep} at depth 3+). \
             Use `format: json` (MCP) or `--json` (CLI) for the full list, or a `path#symbol` target to narrow.",
            rest.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use klens_core::EdgeRelation;

    use super::*;

    fn hit(path: &str, line: usize, distance: usize, confidence: EdgeConfidence) -> ImpactHit {
        ImpactHit {
            path: path.to_string(),
            enclosing_symbol: None,
            line: Some(line),
            relation: EdgeRelation::References,
            confidence,
            distance,
            evidence: format!("{path}:L{line}"),
            snippet: None,
        }
    }

    #[test]
    fn groups_by_file_orders_by_closeness_and_caps_with_a_footer() {
        let mut hits = Vec::new();
        for file in 0..120 {
            let distance = 1 + file % 5;
            for line in 1..=10 {
                hits.push(hit(
                    &format!("src/f{file:03}.rs"),
                    line,
                    distance,
                    EdgeConfidence::Inferred,
                ));
            }
        }
        hits.push(hit("src/zz_direct.rs", 7, 1, EdgeConfidence::Extracted));

        let mut out = String::new();
        write_grouped_hits(&mut out, &hits);
        let lines: Vec<&str> = out.lines().collect();

        assert_eq!(lines.len(), MAX_TEXT_FILES + 1, "{out}");
        assert!(
            lines[0].contains("src/zz_direct.rs"),
            "extracted d=1 first: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("L1, L2, L3, L4, L5, L6, +4 more"),
            "{}",
            lines[1]
        );
        assert!(
            lines.last().unwrap().contains("omitted 91 more files"),
            "{out}"
        );
        assert!(out.len() < 4_000, "text form is {} bytes", out.len());
    }

    #[test]
    fn confidence_shown_is_the_one_of_the_closest_hits() {
        let hits = vec![
            hit("src/a.rs", 3, 3, EdgeConfidence::Extracted),
            hit("src/a.rs", 9, 1, EdgeConfidence::Inferred),
        ];
        let mut out = String::new();
        write_grouped_hits(&mut out, &hits);
        assert!(out.contains("[d=1 | Inferred |"), "{out}");
    }
}
