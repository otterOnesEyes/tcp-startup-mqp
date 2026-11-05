#!/usr/bin/env python3
import os
import shutil
import argparse
from pathlib import Path


def collect_graphs(base_dir):
    base_path = Path(base_dir)
    if not base_path.is_dir():
        print(f"Error: '{base_dir}' is not a valid directory.")
        return

    # Create a summary directory at the root of the provided session folder
    summary_dir = base_path / "Summary_Detailed_Logs"
    summary_dir.mkdir(exist_ok=True)

    found_any = False

    # Iterate through each algorithm folder
    for algo_dir in base_path.iterdir():
        if not algo_dir.is_dir() or algo_dir.name == "Summary_Detailed_Logs":
            continue

        algo_name = algo_dir.name
        algo_summary = summary_dir / algo_name

        # Recursively find all detailed_log_graph.png files in this algorithm's folder
        graphs = list(algo_dir.rglob("detailed_log_graph.png"))

        if graphs:
            found_any = True
            algo_summary.mkdir(exist_ok=True)
            print(f"Found {len(graphs)} detailed log graphs for '{algo_name}'. Copying...")

            for graph_path in graphs:
                # Extract run number and server ID from the path to avoid name collisions
                run_name = "unknown_run"
                for part in graph_path.parts:
                    if part.startswith("run_"):
                        run_name = part
                        break

                server_id = "unknown_server"
                parts = graph_path.parts
                if "servers" in parts:
                    idx = parts.index("servers")
                    if idx + 1 < len(parts):
                        server_id = parts[idx + 1]

                # Rename the copied file to include the run and server info
                new_filename = f"{run_name}_{server_id}_detailed_log_graph.png"
                dest_path = algo_summary / new_filename

                shutil.copy2(graph_path, dest_path)
                print(f"  -> Saved: {dest_path.relative_to(base_path)}")


    if found_any:
        print(f"\nSuccess! All summary graphs have been collected in: {summary_dir.resolve()}")
    else:
        print(f"No 'detailed_log_graph.png' files were found in '{base_dir}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect and group detailed_log_graph.png files from test runs.")
    parser.add_argument(
        "session_dir",
        help="Path to the session directory (e.g., ./iperf3_download_results/2026-11-02_16-10-00/)"
    )
    args = parser.parse_args()

    collect_graphs(args.session_dir)
