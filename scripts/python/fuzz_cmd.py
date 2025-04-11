import os
import argparse
import utils

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Docker commands for Truman fuzzing or evaluation.")
    parser.add_argument('--fuzz', action='store_true', help="Generate commands for fuzzing with the --fuzz flag")
    parser.add_argument('--evaluation', action='store_true', help="Generate commands for evaluation with the --evaluation flag")
    args = parser.parse_args()

    env = utils.get_env()
    prefix = f'python3 /home/{os.getenv("USER")}/truman/scripts/python/fuzz.py'

    for tool in ['morphuzz', 'truman']:
        for target in env.targets:
            print(f'{prefix} -e --fork -t {target} --tool {tool}')
