// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus

//! `attest-ledger`: an independent verifier for record chains and audit
//! segments.
//!
//! The verifier reads records from disk and recomputes every hash itself; it
//! shares no state with whatever produced them.
//!
//! Exit codes: 0 verified; 1 invalid, refused, or unreadable input; 2 a
//! command-line syntax error; 3 (`verify --roots` only) the chain is intact
//! under the anchor's embedded key, but that key is not authorised by the
//! pinned trust roots. Without `--roots`, a signed anchor is verified against
//! its embedded key only, which proves integrity, not who signed it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use attest_ledger_core::{
    TrustRootsV1, trust_roots_digest, validate_trust_roots, verify_audit_chain,
    verify_audit_chain_with_head, verify_chain, verify_chain_with_anchor,
    verify_chain_with_anchor_and_roots, verify_chain_with_head, verify_chain_with_head_and_roots,
};
use attest_ledger_types::{ChainAnchor, HeadCommitmentV1, LedgerRecord};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "attest-ledger",
    version,
    about = "Independent verifier for attest-ledger record chains and audit segments."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a record chain (one LedgerRecord JSON per line).
    Verify {
        /// Path to the JSONL chain file.
        chain: PathBuf,
        /// Optional signed anchor JSON to check the chain's root and signature.
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Fail unless a signed anchor is supplied (reject unsigned chains).
        #[arg(long)]
        require_signed: bool,
        /// Trusted expected head commitment JSON for a complete-chain check.
        #[arg(long)]
        head: Option<PathBuf>,
        /// Fail unless both a trusted head and signed anchor are supplied.
        #[arg(long)]
        require_head: bool,
        /// Pinned trust roots JSON: authenticate the anchor's signer instead
        /// of trusting the key the anchor carries. Requires --anchor.
        #[arg(long)]
        roots: Option<PathBuf>,
        /// Expected `sha256:` digest of the --roots set's canonical form.
        #[arg(long, requires = "roots")]
        roots_digest: Option<String>,
        /// Fail unless pinned trust roots are supplied.
        #[arg(long)]
        require_roots: bool,
    },
    /// Verify an audit segment (one JSON record per line, ending in an optional
    /// segment head).
    VerifyAudit {
        /// Path to the JSONL segment file.
        segment: PathBuf,
        /// Expected genesis hash binding this segment to a prior segment's head
        /// (cross-segment continuity).
        #[arg(long)]
        genesis: Option<String>,
        /// Trusted expected head commitment JSON for a closed-segment check.
        #[arg(long)]
        head: Option<PathBuf>,
        /// Fail rather than fall back to integrity-only verification.
        #[arg(long)]
        require_head: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Verify {
            chain,
            anchor,
            require_signed,
            head,
            require_head,
            roots,
            roots_digest,
            require_roots,
        } => run_verify(
            &chain,
            anchor.as_deref(),
            require_signed,
            head.as_deref(),
            require_head,
            RootsArgs {
                path: roots.as_deref(),
                digest: roots_digest.as_deref(),
                required: require_roots,
            },
        ),
        Command::VerifyAudit {
            segment,
            genesis,
            head,
            require_head,
        } => run_verify_audit(&segment, genesis.as_deref(), head.as_deref(), require_head)
            .map_err(Failure::Invalid),
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(Failure::Invalid(msg)) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
        Err(Failure::NotAuthenticated(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(EXIT_NOT_AUTHENTICATED)
        }
    }
}

/// Exit code for a chain that is intact under its anchor's embedded key but
/// whose signer the pinned roots do not authorise.
const EXIT_NOT_AUTHENTICATED: u8 = 3;

enum Failure {
    /// Exit 1.
    Invalid(String),
    /// Exit 3.
    NotAuthenticated(String),
}

impl From<String> for Failure {
    fn from(msg: String) -> Self {
        Self::Invalid(msg)
    }
}

struct RootsArgs<'a> {
    path: Option<&'a Path>,
    digest: Option<&'a str>,
    required: bool,
}

const EMBEDDED_KEY_NOTE: &str = "note: integrity only (the anchor was verified against its embedded key, not authenticated); pass --roots to authenticate its signer";

fn run_verify(
    chain: &Path,
    anchor: Option<&Path>,
    require_signed: bool,
    head: Option<&Path>,
    require_head: bool,
    roots: RootsArgs<'_>,
) -> Result<String, Failure> {
    if roots.required && roots.path.is_none() {
        return Err(
            "--require-roots was set but no --roots was supplied: cannot authenticate the anchor's signer"
                .to_owned()
                .into(),
        );
    }
    if roots.path.is_some() && anchor.is_none() {
        return Err(
            "--roots was supplied without --anchor: trust roots authenticate a signed anchor"
                .to_owned()
                .into(),
        );
    }
    if require_head && (head.is_none() || anchor.is_none()) {
        return Err(
            "--require-head was set but --head and --anchor were not both supplied: cannot verify record-chain completeness"
                .to_owned()
                .into(),
        );
    }
    if head.is_some() && anchor.is_none() {
        return Err(
            "--head was supplied without --anchor: a record-chain head must bind a verified signed anchor"
                .to_owned()
                .into(),
        );
    }
    if require_signed && anchor.is_none() {
        return Err(
            "--require-signed was set but no --anchor was supplied: cannot verify an unsigned chain"
                .to_owned()
                .into(),
        );
    }
    if let Some(roots_path) = roots.path {
        let anchor_path = anchor.expect("--roots without --anchor was refused above");
        return run_verify_rooted(chain, anchor_path, head, roots_path, roots.digest);
    }
    let records: Vec<LedgerRecord> =
        read_jsonl(chain).map_err(|e| format!("chain INVALID: {e}"))?;
    match (anchor, head) {
        (Some(anchor_path), Some(head_path)) => {
            let anchor: ChainAnchor =
                read_json(anchor_path).map_err(|e| format!("chain INVALID: {e}"))?;
            let head: HeadCommitmentV1 =
                read_json(head_path).map_err(|e| format!("chain INVALID: {e}"))?;
            verify_chain_with_head(&anchor, &records, &head)
                .map_err(|e| format!("chain INVALID: {e}"))?;
            eprintln!("{EMBEDDED_KEY_NOTE}");
            Ok(format!(
                "chain VERIFIED: {} record(s), anchor signature valid, trusted head matched",
                records.len()
            ))
        }
        (Some(path), None) => {
            let anchor: ChainAnchor = read_json(path).map_err(|e| format!("chain INVALID: {e}"))?;
            verify_chain_with_anchor(&anchor, &records)
                .map_err(|e| format!("chain INVALID: {e}"))?;
            eprintln!("{EMBEDDED_KEY_NOTE}");
            Ok(format!(
                "chain VERIFIED: {} record(s), anchor signature valid, integrity only (no trusted head supplied)",
                records.len()
            ))
        }
        (None, None) => {
            verify_chain(&records).map_err(|e| format!("chain INVALID: {e}"))?;
            Ok(format!(
                "chain VERIFIED: {} record(s), integrity only (no trusted head supplied; no anchor supplied)",
                records.len()
            ))
        }
        (None, Some(_)) => unreachable!("head without anchor was refused before file reads"),
    }
}

/// `verify --roots`: authenticate the anchor's signer against pinned roots.
/// Every input is read and the root set validated before any verification.
fn run_verify_rooted(
    chain: &Path,
    anchor_path: &Path,
    head: Option<&Path>,
    roots_path: &Path,
    expected_digest: Option<&str>,
) -> Result<String, Failure> {
    let invalid = |e: String| Failure::Invalid(format!("chain INVALID: {e}"));
    let roots: TrustRootsV1 = read_json(roots_path).map_err(invalid)?;
    validate_trust_roots(&roots).map_err(|e| invalid(format!("invalid trust roots: {e}")))?;
    let digest = trust_roots_digest(&roots);
    if let Some(expected) = expected_digest {
        if expected != digest {
            return Err(invalid(format!(
                "trust roots digest {digest} does not match --roots-digest {expected}"
            )));
        }
    }
    let records: Vec<LedgerRecord> = read_jsonl(chain).map_err(invalid)?;
    let anchor: ChainAnchor = read_json(anchor_path).map_err(invalid)?;
    let head: Option<HeadCommitmentV1> = head.map(read_json).transpose().map_err(invalid)?;
    let rooted = match &head {
        Some(head) => verify_chain_with_head_and_roots(&anchor, &records, head, &roots),
        None => verify_chain_with_anchor_and_roots(&anchor, &records, &roots),
    };
    let tail = if head.is_some() {
        "trusted head matched"
    } else {
        "integrity only (no trusted head supplied)"
    };
    match rooted {
        Ok(key_id) => Ok(format!(
            "chain VERIFIED: {} record(s), anchor signature valid, signer authenticated by pinned root {key_id} (roots {digest}), {tail}",
            records.len()
        )),
        Err(e) if e.is_authorisation_refusal() => {
            // Not authorised. Say whether the chain is at least intact under
            // the embedded key, so tampering (exit 1) is never reported as a
            // mere authorisation gap (exit 3).
            let intact = match &head {
                Some(head) => {
                    verify_chain_with_head(&anchor, &records, head).map_err(|e| e.to_string())
                }
                None => verify_chain_with_anchor(&anchor, &records).map_err(|e| e.to_string()),
            };
            match intact {
                Ok(()) => Err(Failure::NotAuthenticated(format!(
                    "chain NOT AUTHENTICATED: {} record(s) intact under the anchor's embedded key only: {e} (roots {digest})",
                    records.len()
                ))),
                Err(_) => Err(invalid(e.to_string())),
            }
        }
        Err(e) => Err(invalid(e.to_string())),
    }
}

fn run_verify_audit(
    segment: &Path,
    genesis: Option<&str>,
    head: Option<&Path>,
    require_head: bool,
) -> Result<String, String> {
    if require_head && head.is_none() {
        return Err(
            "--require-head was set but no --head was supplied: cannot verify closed audit-segment completeness"
                .into(),
        );
    }
    let records: Vec<Value> =
        read_jsonl(segment).map_err(|e| format!("audit segment INVALID: {e}"))?;
    match head {
        Some(path) => {
            let head: HeadCommitmentV1 =
                read_json(path).map_err(|e| format!("audit segment INVALID: {e}"))?;
            let expected_genesis = genesis.unwrap_or(&head.anchor_identity);
            verify_audit_chain_with_head(&records, expected_genesis, &head)
                .map_err(|e| format!("audit segment INVALID: {e}"))?;
            Ok(format!(
                "audit segment VERIFIED: {} record(s), trusted head matched",
                records.len()
            ))
        }
        None => {
            verify_audit_chain(&records, genesis)
                .map_err(|e| format!("audit segment INVALID: {e}"))?;
            Ok(format!(
                "audit segment VERIFIED: {} record(s), integrity only (no trusted head supplied)",
                records.len()
            ))
        }
    }
}

/// Read a JSONL file into a vector, one deserialized value per non-blank line.
fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: parse error: {e}", path.display(), n + 1))?;
        out.push(value);
    }
    Ok(out)
}

/// Read a single JSON document from a file.
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}
