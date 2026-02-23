"""
# README: Hayabusa Runner Script

This script acts as a wrapper around the Hayabusa CLI tool to process Windows
event log files (.evtx) for a digital forensics ML pipeline.

## How to Use
- Provide the path to a single .evtx file or a directory containing .evtx files
  using the `--evtx` argument.
- Optionally specify the path to the Hayabusa binary with `--hayabusa`
  (defaults to `./hayabusa`).
- Use `--dry-run` to preview the Hayabusa command without executing it.

## Where to Get Hayabusa
Download the Hayabusa binary from:
  https://github.com/Yamato-Security/hayabusa/releases

## Sample EVTX Files
You can find sample .evtx files in the hayabusa-sample-evtx repository:
  https://github.com/Yamato-Security/hayabusa-sample-evtx

## Example Usage

# Single file
python hayabusa_runner.py --evtx ./logs/Security.evtx --hayabusa ./hayabusa

# Directory of evtx files
python hayabusa_runner.py --evtx ./logs/ --hayabusa ./hayabusa

# Dry run to preview command
python hayabusa_runner.py --evtx ./logs/ --hayabusa ./hayabusa --dry-run
"""

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


EXPECTED_COLUMNS = [
    "Timestamp",
    "Computer",
    "Channel",
    "EventID",
    "Level",
    "RuleTitle",
    "Details",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wrapper script for Hayabusa CLI to process EVTX files."
    )
    parser.add_argument(
        "--evtx",
        required=True,
        help="Path to a .evtx file or directory of .evtx files",
    )
    parser.add_argument(
        "--hayabusa",
        default="./hayabusa",
        help="Path to Hayabusa binary (default: ./hayabusa)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the Hayabusa command that would be run without executing it",
    )
    return parser.parse_args()


def validate_paths(evtx_path: Path, hayabusa_path: Path) -> None:
    if not evtx_path.exists():
        print(f"Error: EVTX path '{evtx_path}' does not exist.")
        sys.exit(1)

    if not hayabusa_path.is_file():
        print(f"Error: Hayabusa binary '{hayabusa_path}' not found or is not a file.")
        sys.exit(1)


def get_timestamped_filename() -> str:
    """Return a filename like hayabusa_20240101_153045.csv using UTC time."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"hayabusa_{ts}.csv"


def build_command(
    hayabusa_path: Path, evtx_path: Path, output_csv: Path
) -> list[str]:
    input_flag = "-d" if evtx_path.is_dir() else "-f"
    return [
        str(hayabusa_path),
        "csv-timeline",
        input_flag, str(evtx_path),
        "-o", str(output_csv),
        "-w",
        "-p", "verbose",
        "-U",
        "--no-color",
        "--quiet",
    ]


def run_hayabusa(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}\n")
    try:
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"\nError: Hayabusa exited with return code {e.returncode}.")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: Hayabusa binary could not be executed. Check the path and permissions.")
        sys.exit(1)


def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        print("Warning: Hayabusa produced no output — the CSV is missing or empty.")
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"Error loading CSV '{path}': {e}")
        sys.exit(1)


def validate_and_report(df: pd.DataFrame) -> None:
    if df.empty:
        print("Warning: No rows found in output.")
        return

    missing = [col for col in EXPECTED_COLUMNS if col not in df.columns]
    if missing:
        print(f"Warning: Missing expected columns: {', '.join(missing)}")

    print(f"\n--- Validation Summary ---")
    print(f"Row count:               {len(df)}")

    if "Computer" in df.columns:
        print(f"Unique computers:        {df['Computer'].nunique()}")

    if "Channel" in df.columns:
        print(f"Unique channels:         {df['Channel'].nunique()}")

    if "Level" in df.columns:
        print("\nSeverity level distribution:")
        print(df["Level"].value_counts().to_string())


def main() -> None:
    args = parse_args()

    evtx_path = Path(args.evtx)
    hayabusa_path = Path(args.hayabusa)

    validate_paths(evtx_path, hayabusa_path)

    output_dir = Path("./output")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamped_csv = output_dir / get_timestamped_filename()
    clean_csv = output_dir / "hayabusa_output.csv"

    command = build_command(hayabusa_path, evtx_path, timestamped_csv)

    if args.dry_run:
        print("Would run: " + " ".join(command))
        sys.exit(0)

    run_hayabusa(command)

    df = load_csv(timestamped_csv)
    validate_and_report(df)

    if not df.empty:
        df.to_csv(clean_csv, index=False)
        print(f"\nClean output saved to:  {clean_csv}")
        print(f"Total rows exported:    {len(df)}")
    else:
        print(f"\nNo data to write. Raw output (if any): {timestamped_csv}")


if __name__ == "__main__":
    main()
