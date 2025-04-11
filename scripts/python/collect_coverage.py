import argparse
from pathlib import Path
import utils
import subprocess
import logging
import multiprocessing
import os

def execute_cmd(args):
    """Execute a single command."""
    cmd, env_scripts_python_dir, debug = args
    print(f"Executing command in process ID: {os.getpid()}")
    if debug:
        print(' '.join(cmd))
    else:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Command '{' '.join(cmd)}' failed with return code {e.returncode}")
        except Exception as e:
            logging.error(f"Command '{' '.join(cmd)}' failed with exception: {e}")

def process(args):
    """Process the base directory and execute commands in parallel."""
    base_path = args.base
    suffix = args.filter
    debug = args.debug

    if not base_path.exists() or not base_path.is_dir():
        raise ValueError("The specified base directory does not exist or is not a directory.")

    # Retrieve environment variable here to avoid pickling issues
    env = utils.get_env()
    env_scripts_python_dir = env.scripts_python_dir

    commands = []

    evaluation_flag = ['-e'] if 'evaluation' in str(base_path) else []
    extra_flag = ['--cov_record'] if args.trend else []

    for subdir in base_path.iterdir():
        if subdir.is_dir() and suffix in subdir.name:
            parts = subdir.name.split('_')
            if len(parts) < 2:
                logging.error(f"Unexpected subdirectory name format: {subdir.name}")
                continue
            tool = parts[0]
            target = parts[1]
            cmd = [
                'python3', f'{env_scripts_python_dir}/fuzz.py',
                '--collect', str(subdir),
                '--target', target,
                '--tool', tool
            ] + evaluation_flag + extra_flag
            commands.append((cmd, env_scripts_python_dir, debug))

    # Print number of commands and number of workers
    print(f"Total commands to execute: {len(commands)}")
    num_workers = args.workers if args.workers else multiprocessing.cpu_count()
    print(f"Using num_workers={num_workers}")

    # Execute commands in parallel using multiprocessing.Pool
    with multiprocessing.Pool(processes=num_workers) as pool:
        pool.map(execute_cmd, commands)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traverse directories, filter by suffix, and execute fuzz.py on them in parallel.")
    parser.add_argument("--base", type=Path, help="The base directory to search.", required=True)
    parser.add_argument("--filter", type=str, default="xxx", help="Suffix to filter subdirectories by.")
    parser.add_argument("--trend", action="store_true", help="Collect coverage figure.")
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-w', '--workers', type=int, help="Number of worker processes for parallel execution.")

    args = parser.parse_args()

    process(args)
