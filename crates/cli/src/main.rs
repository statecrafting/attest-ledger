// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus

//! `attest-ledger`: an independent verifier for record chains and audit
//! segments.
//!
//! The verifier reads records from disk and recomputes every hash itself; it
//! shares no state with whatever produced them. Exit 0 on a clean verify,
//! exit 1 with a specific diagnostic on tamper.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use attest_ledger_core::{
    verify_audit_chain, verify_audit_chain_with_head, verify_chain, verify_chain_with_anchor,
    verify_chain_with_head,
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
        } => run_verify(
            &chain,
            anchor.as_deref(),
            require_signed,
            head.as_deref(),
            require_head,
        ),
        Command::VerifyAudit {
            segment,
            genesis,
            head,
            require_head,
        } => run_verify_audit(&segment, genesis.as_deref(), head.as_deref(), require_head),
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn run_verify(
    chain: &Path,
    anchor: Option<&Path>,
    require_signed: bool,
    head: Option<&Path>,
    require_head: bool,
) -> Result<String, String> {
    if require_head && (head.is_none() || anchor.is_none()) {
        return Err(
            "--require-head was set but --head and --anchor were not both supplied: cannot verify record-chain completeness"
                .into(),
        );
    }
    if head.is_some() && anchor.is_none() {
        return Err(
            "--head was supplied without --anchor: a record-chain head must bind a verified signed anchor"
                .into(),
        );
    }
    if require_signed && anchor.is_none() {
        return Err(
            "--require-signed was set but no --anchor was supplied: cannot verify an unsigned chain"
                .into(),
        );
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
            Ok(format!(
                "chain VERIFIED: {} record(s), anchor signature valid, trusted head matched",
                records.len()
            ))
        }
        (Some(path), None) => {
            let anchor: ChainAnchor = read_json(path).map_err(|e| format!("chain INVALID: {e}"))?;
            verify_chain_with_anchor(&anchor, &records)
                .map_err(|e| format!("chain INVALID: {e}"))?;
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
