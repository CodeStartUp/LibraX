use librax_enrichment::Inventory;
use librax_types::{CanonicalEvent, SecuritySignal};

/// What this incident has *not* established.
///
/// Derived from the evidence rather than written by hand, so the list shrinks as
/// the picture improves instead of becoming stale boilerplate.
pub fn derive(
    signals: &[SecuritySignal],
    events: &[CanonicalEvent],
    inventory: &Inventory,
    unmapped_techniques: &[String],
) -> Vec<String> {
    let mut unknowns: Vec<String> = Vec::new();

    let fired = |detector: &str| signals.iter().any(|s| s.detector_id == detector);

    // Staging without an observed transfer: the data may or may not have left.
    let outbound_transfer = events.iter().any(|e| {
        e.attributes
            .get("bytes_out")
            .and_then(|v| v.as_f64())
            .is_some_and(|bytes| bytes > 100_000_000.0)
    });
    if fired("data_staging") && !outbound_transfer {
        unknowns.push(
            "Exfiltration is unconfirmed. An archive was staged, but no outbound transfer \
             large enough to carry it has been observed."
                .to_string(),
        );
    }

    // An encoded command was seen, not read.
    if events.iter().any(|e| {
        e.command_line()
            .is_some_and(|c| c.to_ascii_lowercase().contains("-enc"))
    }) {
        unknowns.push(
            "The encoded PowerShell payload has not been decoded, so the instructions it \
             carried are unknown."
                .to_string(),
        );
    }

    // Ransomware preparation is not ransomware detonation.
    if fired("ransomware_indicator") {
        let encrypted = events.iter().any(|e| {
            e.attributes
                .get("files_encrypted")
                .and_then(|v| v.as_f64())
                .is_some_and(|n| n > 0.0)
        });
        if !encrypted {
            unknowns.push(
                "No file has been confirmed encrypted. Recovery was disabled and files were \
                 being rewritten, which is preparation rather than proof of detonation."
                    .to_string(),
            );
        }
    }

    // Blind spots are part of the picture.
    let (covered, expected, percent) = inventory.edr_coverage();
    if covered < expected {
        unknowns.push(format!(
            "EDR covers {covered} of {expected} endpoints ({percent:.1}%). Activity on the \
             remaining {} endpoints would not be visible to this investigation.",
            expected - covered
        ));
    }

    if !unmapped_techniques.is_empty() {
        unknowns.push(format!(
            "{} proposed ATT&CK technique(s) were rejected as unrecognised and are reported \
             unmapped rather than guessed: {}.",
            unmapped_techniques.len(),
            unmapped_techniques.join(", ")
        ));
    }

    let unmapped_signals = signals.iter().filter(|s| s.mitre.is_empty()).count();
    if unmapped_signals > 0 {
        unknowns.push(format!(
            "{unmapped_signals} detection(s) in this incident have no ATT&CK mapping, because \
             the observed behaviour does not by itself evidence a technique."
        ));
    }

    // Attribution is not something this system can establish.
    if signals.iter().any(|s| s.detector_id == "c2_connection") {
        unknowns.push(
            "The operator behind the command-and-control infrastructure is unidentified. \
             LibraX correlates behaviour and does not attribute it to a named group."
                .to_string(),
        );
    }

    unknowns
}
