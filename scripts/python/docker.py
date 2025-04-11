import os
import argparse
import subprocess

import utils

env = utils.get_env()
IMAGE_NAME = env.project_name

def container_exists(container_name):
    result = subprocess.run(['docker', 'ps', '-a', '-q', '-f', f'name={container_name}'], stdout=subprocess.PIPE)
    return bool(result.stdout.strip())

def build_container():
    """Build the Docker container."""
    try:
        os.chdir(env.config_dir)
        uid = os.getuid()
        gid = os.getgid()

        if container_exists(env.container_name):
            subprocess.run(['docker', 'stop', env.container_name])
            subprocess.run(['docker', 'rm', env.container_name])
            print(f'Container {env.container_name} has been stopped and removed.')

        # Build the Docker image with the current user's UID and GID
        subprocess.run([
            "docker", "build",
            "--build-arg", f"USERNAME={os.getenv('USER')}",
            "--build-arg", f"UID={uid}",
            "--build-arg", f"GID={gid}",
            "-t", IMAGE_NAME, "."
        ], check=True)
        print(f"Successfully built the Docker image '{IMAGE_NAME}'")

        run_command = [
            "docker", "run", "-itd", "-v", "/dev:/dev", '--privileged',
            "-v", f"{env.project_dir}:/home/{os.getenv('USER')}/{env.project_name}",
            "--name", f"{env.container_name}",
            IMAGE_NAME
        ]
        if os.path.exists("/media/hdd0"):
            run_command.insert(5, "-v")
            run_command.insert(6, "/media/hdd0:/mnt")
        print(run_command)

        subprocess.run(run_command)
        print(f"Successfully started the Docker container '{env.container_name}'")
    except subprocess.CalledProcessError as e:
        print(f"Failed to build or run the Docker image '{IMAGE_NAME}'. Error: {e}")

def is_container_running(container_name):
    """Check if the Docker container is running."""
    result = subprocess.run(['docker', 'ps', '-q', '-f', f'name={container_name}'], stdout=subprocess.PIPE)
    return bool(result.stdout.strip())

def run_container():
    """Run the Docker container."""

    # utils.run_cmd('sudo chmod 777 /dev/udmabuf')
    try:
        if not is_container_running(env.container_name):
            print(f"The Docker container '{env.container_name}' is not running. Attempting to start it...")
            subprocess.run(['docker', 'start', env.container_name], check=True)
            print(f"Successfully started the Docker container '{env.container_name}'.")

        new_path = "$HOME/truman/install/llvm/bin:$PATH"
        new_ld_library_path = "$HOME/truman/install/libvirtfuzz/lib:$HOME/truman/install/protobuf/lib:$LD_LIBRARY_PATH"

        run_command = [
            "docker", "exec", "-it", f"{env.container_name}", "sh", "-c",
            f"export PATH={new_path} && export LD_LIBRARY_PATH={new_ld_library_path} && exec fish"
        ]
        subprocess.run(run_command)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start the Docker container '{env.container_name}'. Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Build and run the Docker container.")
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build the Docker image and run the container"
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the Docker container"
    )

    args = parser.parse_args()

    if args.build:
        build_container()
    elif args.run:
        run_container()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
