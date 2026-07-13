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

use attest_ledger_core::{verify_audit_chain, verify_chain, verify_chain_with_anchor};
use attest_ledger_types::{ChainAnchor, LedgerRecord};
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
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Verify {
            chain,
            anchor,
            require_signed,
        } => run_verify(&chain, anchor.as_deref(), require_signed),
        Command::VerifyAudit { segment, genesis } => run_verify_audit(&segment, genesis.as_deref()),
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

fn run_verify(chain: &Path, anchor: Option<&Path>, require_signed: bool) -> Result<String, String> {
    let records: Vec<LedgerRecord> = read_jsonl(chain)?;
    if require_signed && anchor.is_none() {
        return Err(
            "--require-signed was set but no --anchor was supplied: cannot verify an unsigned chain"
                .into(),
        );
    }
    match anchor {
        Some(path) => {
            let anchor: ChainAnchor = read_json(path)?;
            verify_chain_with_anchor(&anchor, &records)
                .map_err(|e| format!("chain INVALID: {e}"))?;
            Ok(format!(
                "chain VERIFIED: {} record(s), anchor signature valid",
                records.len()
            ))
        }
        None => {
            verify_chain(&records).map_err(|e| format!("chain INVALID: {e}"))?;
            Ok(format!(
                "chain VERIFIED: {} record(s), integrity only (no anchor supplied)",
                records.len()
            ))
        }
    }
}

fn run_verify_audit(segment: &Path, genesis: Option<&str>) -> Result<String, String> {
    let records: Vec<Value> = read_jsonl(segment)?;
    verify_audit_chain(&records, genesis).map_err(|e| format!("audit segment INVALID: {e}"))?;
    Ok(format!(
        "audit segment VERIFIED: {} record(s)",
        records.len()
    ))
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
