import json
import subprocess
from pathlib import Path

from . import environment


class EnableConfig(object):

    def __init__(self, args):
        self.__setup(args)
        self.__check()

    def __setup(self, args):
        self.config_type = args.config_type
        self.config_file = Path(args.config_file)
        self.env = environment.get_env()

    def __check(self):
        if not self.env.config_linux_enable_config.exists():
            raise Exception(f"The json file {self.env.config_json} doesn't "
                            "exist.")
        if not self.config_file.exists():
            raise Exception(f"The config file {self.config_file} doesn't "
                            "exist.")

    def _enable_config(self, mode, config_name, config_status=''):
        cmd = (f'{self.env.third_party_linux_config_tool} --file '
               f'{self.config_file} -{mode} {config_name} {config_status}')
        print(cmd)
        subprocess.run(cmd, shell=True)

    def process(self):
        with open(self.env.config_linux_enable_config, 'r') as f:
            content = json.loads(f.read())
        for config_type, config in content.items():
            if config_type not in self.config_type:
                continue
            for config_name, config_status in config.items():
                if 'd' == config_status or 'e' == config_status or 'm' == config_status:
                    mode = config_status
                    self._enable_config(mode, config_name)
                elif 'CMDLINE' == config_name:
                    self._enable_config('-set-str', config_name, config_status)
                else:
                    self._enable_config('-set-val', config_name, config_status)
