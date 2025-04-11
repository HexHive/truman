import os
import socket
import subprocess
from datetime import date

def run_cmd(cmd, check=True, env=None, capture_output=False, timeout=None):
    print(f'\n[DIR]: {os.getcwd()}')
    print(f'[CMD]: {cmd}')
    try:
        process = subprocess.run(cmd, shell=True, check=check, env=env, capture_output=capture_output, timeout=timeout)
        if capture_output == True:
            print(process.stdout.decode())
            print(process.stderr.decode())
        return process
    except subprocess.TimeoutExpired as e:
        print(f"Command timed out!")
        if capture_output == True:
            return e.stdout
        else:
            return None
    except subprocess.CalledProcessError as e:
        if capture_output == True:
            return e.stderr

        if check == True:
            raise Exception(f"Command Error {e}")

        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

def get_date():
    current_date = date.today()
    formatted_date = current_date.strftime('%m%d')
    return formatted_date
