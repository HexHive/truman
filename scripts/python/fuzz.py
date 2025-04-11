import re
import os
import git
import yaml
import time
import psutil
import logging
import argparse
import threading
import schedule
import threading
import subprocess
import multiprocessing
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

import utils

evaluation_time = 60 * 60 * 24 * 2 + 60
# evaluation_time = 60 * 60 * 24 + 60

class QEMUFuzz(object):

    target2file = {
            "i6300esb":                 "i6300esb.c",
            "i82550":                   "eepro100.c",
            "tulip":                    "tulip.c",
            "vmxnet3":                  "vmxnet3.c",
            "ehci":                     "hcd-ehci.c",
            "ohci":                     "ohci.c",
            "pvscsi":                   "vmw_pvscsi.c",
            "xhci":                     "hcd-xhci.c",
            "am53c974":                 "esp-pci.c",
            "ati-vga":                  "ati.c",
            "igb":                      "igb_core.c",
            "intel-hda":                "intel-hda.c",
            'ahci-hd':                  "ide/ahci.c",
            'fdc-isa':                  "fdc.c",
            'megaraid':                 "megasas.c",
            'sdhci':                    "sd/sdhci.c",
            'sdhci-v3':                 "sd/sdhci.c",
            'e1000e':                   "e1000e_core.c",
            'e1000':                    "e1000.c",
            'rtl8139':                  "rtl8139.c",
            'nvme':                     "nvme/ctrl.c",
            'virtio-net-pci-slirp':     "net/virtio-net.c",
            'virtio-blk':               "block/virtio-blk.c",
            'virtio-balloon':           "virtio/virtio-balloon.c",
            'virtio-crypto-pci':        "virtio/virtio-crypto.c",
            'virtio-gpu':               "display/virtio-gpu.c",
            'virtio-scsi':              "scsi/virtio-scsi.c",
            'virtio-iommu':             "virtio/virtio-iommu.c",
            'virtio-mem-pci':           "virtio/virtio-mem.c",
            'virtio-sound':             "audio/virtio-snd.c",
            'sunhme':                   "sunhme.c",
            'ufs':                      "ufs.c",
            'VGA':                      "vga.c",
            'mptsas1068':               "mptsas1068.c",
            "pcnet":                    "pcnet.c",
            "cs4231a":                  "cs4231a.c",
            "ac97":                     "ac97.c",
            "es1370":                   "es1370.c",
            "ne2k":                     "ne2000.c",
            "sb16":                     "sb16.c",
            "cirrus-vga":               "cirrus_vga.c",
            }

    def __init__(self):
        self._setup()
        self._parse_args()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def _setup(self):
        self.env = utils.get_env()
        self.cov_cnt = 1
        os.chdir(f'{self.env.third_party_qemu_dir}')
        self.git_version = git.Repo(search_parent_directories=True).head.object.hexsha[:8]
        utils.run_cmd(f'cp {self.env.config_dbm_dir}/* {self.env.out_static_analysis_dir}')

    def _parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', type=str, default=None, required=True)
        parser.add_argument('-c', '--continuous', action='store_true')
        parser.add_argument('-k', '--kill', action='store_true')
        parser.add_argument('--collect', type=Path, default=None)
        parser.add_argument('--asan', action='store_true')
        parser.add_argument('-e', '--evaluation', action='store_true')
        parser.add_argument('--cov_record', action="store_true")
        parser.add_argument('--fork', action='store_true')
        parser.add_argument('--tool', type=str, choices=['morphuzz', 'truman'], default='truman')
        parser.add_argument('-d', '--debug', action='store_true', default=False)
        parser.add_argument('--arch', choices=self.env.arch, default='x86_64')
        parser.add_argument('--seed', type=str)
        parser.add_argument('--run', action='store_true')
        parser.add_argument('--disable_state', action='store_true')

        self.args = parser.parse_args()

        if self.args.collect:
            found = False
            for key in QEMUFuzz.target2file.keys():
                if key in self.args.target:
                    found = True
                    break
            if not found:
                raise Exception(f"Cannot find {self.args.target} in the targets!")

            if self.args.tool == None:
                raise Exception(f"Please input the --tool")
            self.git_version = ''

        target = self.args.target if self.args.target else "all"
        if self.args.evaluation:
            self.cur_target = f'{self.args.tool}_{target}_{self.git_version}_{time.strftime("%m%d%H%M", time.localtime())}'
            self.evaluation_dir = self.env.out_fuzz_dir / f'evaluation_{time.strftime("%m%d", time.localtime())}' / self.cur_target
            self.cov_record_dir = self.evaluation_dir / 'cov_record'
            if not self.args.collect:
                self.cov_record_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.cur_target = f'{self.args.tool}_{target}_{self.git_version}_generic'
            self.evaluation_dir = self.env.out_fuzz_dir / f'{self.cur_target}'
        self.tmp_dir = self.env.tmp_dir / self.cur_target
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def _run_cmd(self, cmd, continuous=False, check=True, shell=True, env=None, stdout=None):
        if shell:
            print('\n[CMD]:', cmd)
        else:
            print(f'\n[CMD]: {" ".join(cmd)}')
        if continuous:
            return subprocess.Popen(cmd, shell=shell, stdout=stdout, stderr=stdout, env=env).returncode
        else:
            return subprocess.run(cmd, shell=shell, check=check, env=env).returncode

    def _collect_llvm(self, corpus_dir, cov_dir=None):
        target = self.args.target
        suffix = f'{self.args.tool}-{self.git_version}'
        if self.args.evaluation:
            if self.args.tool == 'truman':
                fuzzer = f'{self.env.install_qemu_coverage_dir}/bin/{self.env.truman_fuzz_binary}'
            else:
                fuzzer = f'{self.env.install_qemu_coverage_dir}/bin/{self.env.fuzz_binary}'
        else:
            if self.args.tool == 'truman':
                fuzzer = f'{self.env.build_qemu_truman_coverage_binary}-{self.git_version}'
            else:
                fuzzer = f'{self.env.build_qemu_coverage_binary}'
        if not corpus_dir.is_dir():
            corpus_dir = corpus_dir.parent
        profraw = corpus_dir / f'{target}.profraw'
        profdata = corpus_dir / f'{target}.profdata'
        coverage_dir = self.args.collect / f'coverage-{suffix}-{target}'
        output_format = 'text'
        extra = '--use-color=0'
        os.chdir(corpus_dir)

        device_model = self.env.out_static_analysis_dir / f'{target}.json'
        env = os.environ.copy()

        if cov_dir:
            cov_record_dir = cov_dir.parent

            unique_files = {}
            dir_files = {}

            profraw_dir = cov_record_dir / 'profraw'
            profraw_dir.mkdir(exist_ok=True, parents=True)

            cov_record_coverage_final_dir = self.args.collect / 'final_cov' / f'{target}'
            cov_record_coverage_final_dir.mkdir(parents=True, exist_ok=True)

            for subdir in cov_record_dir.iterdir():
                if not subdir.is_dir():
                    continue
                for subsubdir in subdir.iterdir():
                    if not subsubdir.is_dir():
                        continue
                    dir_files[subdir.stem] = set(file.name for file in subsubdir.iterdir() if file.is_file())
                    for file in subsubdir.iterdir():
                        if not file.is_file():
                            continue
                        file_name = file.name
                        if file_name not in unique_files:
                            unique_files[file_name] = file.resolve()

            unique_file_paths = sorted(unique_files.values())

            seed_pattern = r'(\d{6})'

            if not any(cov_record_coverage_final_dir.iterdir()):
                for file in unique_file_paths:
                    match = re.search(seed_pattern, file.name)
                    if not match:
                        continue
                    profraw_name = f'{match.group(1)}'
                    file_profraw = profraw_dir / f'{target}_{profraw_name}.profraw'
                    result = utils.run_cmd(f'QEMU_DEVICE_MODEL_FILE={device_model} LLVM_PROFILE_FILE={file_profraw} '
                            f'{fuzzer} --fuzz-target=generic-fuzz-{target} -timeout=1 -runs=1 {file}', capture_output=True, env=env)
                    if isinstance(result, bytes):
                        utils.run_cmd(f'rm {file}')

            pattern = re.compile(r"cov_(\d+)")

            os.chdir(profraw_dir)
            cov_dirs = sorted(cov_record_dir.iterdir(), key=lambda x: int(pattern.search(x.name).group(1)) if pattern.search(x.name) else float('inf'))
            for idx, tmp1_dir in enumerate(cov_dirs):
                if idx % 6 != 0:
                    continue  # Skip directories not in the 6th position

                target_index_file = cov_record_coverage_final_dir / f'{tmp1_dir.stem}.txt'
                if target_index_file.exists():
                    continue

                match = pattern.search(tmp1_dir.name)
                if not match:
                    continue
                current_dir_name = tmp1_dir.name
                numeric_part = ''.join(filter(str.isdigit, current_dir_name))
    
                # Convert the numeric part to an integer, subtract 1, and zero-pad back to original length
                previous_numeric_part = str(int(numeric_part) - 6).zfill(len(numeric_part))
                
                # Construct the previous directory name
                previous_dir_name = f"cov_{previous_numeric_part}"

                previous_dir = tmp1_dir.parent / previous_dir_name
                if previous_dir.exists() and previous_dir.is_dir():
                    diff_list = dir_files[tmp1_dir.stem] - dir_files[previous_dir.stem]
                    profraw_list = []
                    for file in diff_list:
                        if target not in file:
                            match = re.search(seed_pattern, file)
                            if not match:
                                continue
                            profraw_name = f'{match.group(1)}'
                            profraw_list.append(f'{target}_{profraw_name}.profraw')
                    profraw_list.append(str(previous_dir / f'{target}' / f'{target}.profdata'))
                else:
                    profraw_list = []
                    tmp2_dir = tmp1_dir / f'{target}'
                    for testcase in tmp2_dir.iterdir():
                        if testcase.is_file() and target not in testcase.name:
                            match = re.search(seed_pattern, str(testcase.name))
                            if not match:
                                continue
                            profraw_name = f'{match.group(1)}'
                            profraw_list.append(f'{target}_{profraw_name}.profraw')

                cov_record_coverage_dir = self.args.collect / 'cov_record_coverage'
                coverage_dir = cov_record_coverage_dir / f'{tmp1_dir.stem}-{suffix}' / f'{target}'

                profdata = (tmp1_dir / f'{target}') / f'{target}.profdata'
                utils.run_cmd(f'llvm-profdata merge -output={profdata} {" ".join(profraw_list)}')
                utils.run_cmd(f'llvm-cov show {fuzzer} '
                        f'-instr-profile={profdata} --format {output_format} -show-expansions '
                        f'{extra} --output-dir={coverage_dir}')

                self._run_cmd(f'cp {coverage_dir / "index.txt"} {target_index_file}', check=False)

            return True
        else:
            utils.run_cmd(f'rm -f *.profraw *.profdata')
            if not os.listdir('./'):
                return True
            files = '*'
            result = utils.run_cmd(f'QEMU_DEVICE_MODEL_FILE={device_model} LLVM_PROFILE_FILE={profraw} '
                    f'{fuzzer} --fuzz-target=generic-fuzz-{target} -timeout=1 -runs=1 {files}', capture_output=True, env=env)
            if isinstance(result, subprocess.CompletedProcess):
                utils.run_cmd(f'llvm-profdata merge -output={profdata} {profraw}')
                utils.run_cmd(f'llvm-cov show {fuzzer} '
                        f'-instr-profile={profdata} --format {output_format} -show-expansions '
                        f'{extra} --output-dir={coverage_dir}')

                index_file = f'{coverage_dir}/index.txt'
                coverage_file = f'{coverage_dir}/cov.txt'
                with open(index_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if QEMUFuzz.target2file[target] not in line:
                            continue
                        with open(coverage_file, 'w') as f2:
                            f2.write(line.split()[-1])

                    if 'virtio' in target:
                        for line in lines:
                            if 'virtio/virtio.c' not in line:
                                continue
                            with open(coverage_file, 'a') as f2:
                                f2.write('\t' + line.split()[-1])
                return True
            elif isinstance(result, bytes):
                lines = result.decode().splitlines()
                entry_dict = {}

                input_pattern = re.compile(r'(Running:|Executed) (\w+)')

                for line in lines:
                    match = input_pattern.search(line)
                    if match:
                        status, input_id = match.groups()
                        if input_id in entry_dict:
                            entry_dict[input_id].add(status)
                        else:
                            entry_dict[input_id] = {status}

                for input_id, statuses in entry_dict.items():
                    if 'Running:' in statuses and 'Executed' not in statuses:
                        utils.run_cmd(f'rm {input_id}*')
                        break
                return False

    def _collect_cov_one(self, corpus_dir, cov_dir=None):
        result = self._collect_llvm(corpus_dir, cov_dir)
        while result is False:
            result = self._collect_llvm(corpus_dir, cov_dir)

    def _draw_image(self, data, result):
        x = range(1, len(data)+1)
        plt.plot(x, data)
        plt.savefig(result)
        plt.clf()

    def _cov_draw(self, cov_dir):
        target = cov_dir.stem
        branch_coverage = ['0']
        branch_count = [0]

        target_excel = cov_dir / f'{target}.xlsx'
        if target_excel.exists():
            print('Already done')
            return

        # Get the list of relevant .txt files
        file_list = sorted([name for name in os.listdir(cov_dir)
                            if os.path.isfile(os.path.join(cov_dir, name)) and 'txt' in name])

        pattern = re.compile(r'cov_(\d+)\.txt')

        # Iterate over files that match the 'cov_XXX.txt' pattern and select every 6th one
        for file_name in file_list:
            match = pattern.search(file_name)
            if match:
                numeric_part = int(match.group(1))  # Extract the numeric part from the filename
                if numeric_part % 6 == 1:  # Check if the file corresponds to every 6th step (e.g., 001, 007, etc.)
                    index = cov_dir / file_name
                    with open(index, 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if QEMUFuzz.target2file[target] not in line:
                                continue
                            lists = line.split()
                            branch_coverage.append(lists[-1])
                            branch_count.append(int(lists[-3]) - int(lists[-2]))

        # Generate the branch count and coverage images
        self._draw_image(branch_count, cov_dir / f'branch_count_{target}.jpg')
        self._draw_image(branch_coverage, cov_dir / f'branch_coverage_{target}.jpg')
        
        # Save the results to Excel and CSV
        df = pd.DataFrame({'Count': branch_count, 'Coverage': branch_coverage})
        df.to_excel(cov_dir / f'{target}.xlsx')
        df.to_csv(cov_dir / f'{target}.csv')

    def _collect_cov_record(self):
        cov_record_dir = self.args.collect / 'cov_record'
        cov_record_coverage_dir = self.args.collect / 'final_cov'
        if not cov_record_dir.exists():
            return
        cov_record_coverage_dir.mkdir(parents=True, exist_ok=True)

        subdirs = [d for d in cov_record_dir.iterdir() if d.is_dir() and d.name.startswith('cov_')]

        # Sort the subdirectories by name and select the last one
        last_subdir = sorted(subdirs, key=lambda x: x.name)[-1]

        for target_dir in last_subdir.iterdir():
            self._collect_cov_one(target_dir, last_subdir)

        for cov_dir in cov_record_coverage_dir.iterdir():
            self._cov_draw(cov_dir)

    def _collect_cov(self):
        if not self.args.collect.exists():
            print('The corpus dir does not exist, please run fuzzing first!')
            return

        if self.args.cov_record:
            tar_name = f'{self.args.collect.name}_coverage_record.tar.gz'
        else:
            tar_name = f'{self.args.collect.name}_coverage.tar.gz'

        os.chdir(self.args.collect)
        if self.args.cov_record:
            self._collect_cov_record()
            os.chdir(self.args.collect)
            self._run_cmd(f'tar -czvf {tar_name} final_cov')
            utils.run_cmd(f'rm -rf cov_record_coverage')
            tar_dir = f'{self.args.collect.parent}'
        else:
            if Path(tar_name).exists():
                return
            self._run_cmd(f'rm -rf coverage')

            tar_dir = f'{self.args.collect.parent}'
            for corpus_dir in (self.args.collect / 'corpus').iterdir():
                self._collect_cov_one(corpus_dir)

            os.chdir(self.args.collect)
            coverage_dir = Path(f'coverage-{self.args.tool}-{self.git_version}-{self.args.target}')
            if not coverage_dir.exists():
                print(f"Warning! The coverage dir {coverage_dir} does not exist!")
                return
            self._run_cmd(f'tar -czvf {tar_name} {coverage_dir}')

        utils.run_cmd(f'cp {tar_name} {tar_dir}')

    def _watch_artifact_dir(self, artifact_dir, cmd, interval=1):
        seen_files = set(os.listdir(artifact_dir))
        while not self.stop_artifact_watch.is_set():
            current_files = set(os.listdir(artifact_dir))
            new_files = current_files - seen_files
            if new_files:
                for new_file in new_files:
                    if 'timeout' in new_file or 'slow' in new_file:
                        continue
                    cmd[-1] = os.path.join(artifact_dir, new_file)
                    try:
                        self._run_cmd(cmd, shell=False)
                    except:
                        print(cmd)
                seen_files.update(new_files)
            time.sleep(interval)

    def _start_artifact_watcher(self, artifact_dir, cmd):
        self.stop_artifact_watch = threading.Event()
        self.artifact_watch_thread = threading.Thread(target=self._watch_artifact_dir, args=(artifact_dir, cmd))
        self.artifact_watch_thread.start()

    def _stop_artifact_watcher(self):
        self.stop_artifact_watch.set()
        self.artifact_watch_thread.join()

    def _fuzz_one(self, target, continuous=False):
        os.chdir(self.tmp_dir)

        corpus_dir = self.evaluation_dir / 'corpus' / f'{target}'
        artifact_dir = self.evaluation_dir / 'artifact' / f'{target}'
        log_file = self.evaluation_dir / 'log' / f'{target}.log'
        corpus_dir.mkdir(exist_ok=True, parents=True)
        artifact_dir.mkdir(exist_ok=True, parents=True)
        log_file.parent.mkdir(exist_ok=True, parents=True)
        profraw = corpus_dir / f'{target}.profraw'

        if self.args.tool == 'truman':
            if self.args.asan:
                fuzzer = f'{self.env.build_qemu_truman_fuzz_with_asan_binary}-{self.git_version}'
            else:
                fuzzer = f'{self.env.build_qemu_truman_fuzz_without_asan_binary}-{self.git_version}'
        else:
            if self.args.asan:
                fuzzer = f'{self.env.build_qemu_fuzz_with_asan_binary}'
            else:
                fuzzer = f'{self.env.build_qemu_fuzz_without_asan_binary}'
        fuzzer = fuzzer.replace('x86_64', self.args.arch)

        if self.args.evaluation:
            if self.args.tool == 'truman':
                fuzzer = f'{self.env.install_qemu_fuzz_without_asan_dir}/bin/{self.env.truman_fuzz_binary}'
            else:
                fuzzer = f'{self.env.install_qemu_fuzz_without_asan_dir}/bin/{self.env.fuzz_binary}'

        env = os.environ.copy()
        qemu_device_model_file = self.env.out_static_analysis_dir / f'{target}.json'

        if self.args.disable_state:
            env['DISABLE_STATE'] = '1'

        env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
        env['QEMU_DEVICE_MODEL_FILE'] = f'{qemu_device_model_file}'

        cmd = []

        free_cpu = self._find_free_cpu()
        if free_cpu is not None:
            cmd += ['taskset', '-c', str(free_cpu)]
        else:
            raise RuntimeError("No free CPU core available")

        cmd += [f'{fuzzer}', f'--fuzz-target=generic-fuzz-{target}',
               f'-artifact_prefix={artifact_dir}/', '-print_pcs=1', '-timeout=1']
        if self.args.tool == 'morphuzz':
            cmd += [f'-len_control=100', f'-dict={self.env.config_fuzz_dict}']
        if not self.args.debug and not self.args.seed and not self.args.run:
            cmd += ['-close_fd_mask=3']
        if self.args.fork:
            cmd += ['-fork=1', '-ignore_crashes=1']
        if self.args.evaluation:
            cmd += [f'-max_total_time={evaluation_time}']
        if self.args.seed:
            cmd += [f'{self.args.seed}']
            env['QTEST_LOG'] = "1"
            env['FUZZ_SERIALIZE_QTEST'] = "1"
            self.args.debug = True
        elif self.args.run:
            cmd += ['-runs=1', f'{corpus_dir}']
            self.args.debug = True
        else:
            cmd += [f'{corpus_dir}']
            self._start_artifact_watcher(artifact_dir, cmd)

        with open(log_file, 'w') as log_file:
            if self.args.debug:
                stdout = None
                continuous = False
            else:
                stdout = log_file

            if self._run_cmd(cmd, continuous, shell=False, env=env, stdout=stdout) is not None and not self.args.seed and not self.args.run:
                self._fuzz_one(target, continuous)
            self._stop_artifact_watcher()

    def _find_free_cpu(self, threshold=10.0):
        cpu_percentages = psutil.cpu_percent(interval=1, percpu=True)
        free_cpu = min(range(len(cpu_percentages)), key=lambda i: cpu_percentages[i])
        if cpu_percentages[free_cpu] < threshold:  # Assuming a CPU is free if its usage is below 100%
            return free_cpu
        else:
            return None

    def _kill(self):
        if self.args.evaluation:
            self.stop_run_continuously.set()
        self._run_cmd(f'rm -rf {self.tmp_dir}')

    def _copy_corpus(self):
        corpus_dir = self.evaluation_dir / 'corpus'
        cov_record_dir = self.cov_record_dir / f'cov_{self.cov_cnt:03}'
        self.cov_cnt += 1
        try:
            self._run_cmd(f'cp -r {corpus_dir} {cov_record_dir}')
        except:
            pass

    def _run_continuously(self, interval=1):
        """Continuously run, while executing pending jobs at each
        elapsed time interval.
        @return cease_continuous_run: threading. Event which can
        be set to cease continuous run. Please note that it is
        *intended behavior that run_continuously() does not run
        missed jobs*. For example, if you've registered a job that
        should run every minute and you set a continuous run
        interval of one hour then your job won't be run 60 times
        at each interval but only once.
        """
        cease_continuous_run = threading.Event()

        class ScheduleThread(threading.Thread):
            @classmethod
            def run(cls):
                while not cease_continuous_run.is_set():
                    schedule.run_pending()
                    time.sleep(interval)

        continuous_thread = ScheduleThread()
        continuous_thread.start()

        return cease_continuous_run

    def process(self):
        if self.args.evaluation and not self.args.collect:
            timer = threading.Timer(evaluation_time, self._kill)
            timer.start()
            schedule.every(10).minutes.do(self._copy_corpus)
            self.stop_run_continuously = self._run_continuously()

        if self.args.kill:
            self._kill()
        elif self.args.collect:
            self._collect_cov()
        else:
            self._fuzz_one(self.args.target,
                           self.args.continuous or not (self.args.evaluation is None))

if __name__ == '__main__':
    qemu_fuzz = QEMUFuzz()
    qemu_fuzz.process()
