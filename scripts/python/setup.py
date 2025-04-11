import os
import git
import yaml
import time
import types
import argparse
import subprocess
from pathlib import Path

import utils

class Setup(object):

    def __init__(self):
        self._setup()
        self._parse_args()
        self._process_args()
        self.devices = \
            ['igb', 'vmxnet3', 'fdc-isa', 'sdhci-v3', 'e1000e', 'xhci', 'ehci', 'nvme', 
             'virtio-net-pci-slirp', 'virtio-blk', 'virtio-balloon', 'virtio-crypto-pci', 'virtio-gpu', 'virtio-scsi',
             'virtio-iommu', 'virtio-mem-pci', 'virtio-sound']
        os.environ['LD_LIBRARY_PATH'] = f'{self.env.install_protobuf_dir}/lib:{os.environ.get("LD_LIBRARTY_PATH", "")}'

    def _setup(self):
        self.env = utils.get_env()
        self.components = []
        self.cpu_count = os.cpu_count()
        self.func_to_path = {}
        self.bb_to_path = {}
        self.ops_list = []

    def _parse_args(self):
        parser = argparse.ArgumentParser()

        parser.add_argument('--build_qemu', type=str,
                choices=['evaluation', 'fuzz_with_asan', 'fuzz_without_asan', 'coverage', 'upstream', 'all'])
        parser.add_argument('--build_llvm', action='store_true')
        parser.add_argument('--build_linux', type=str, choices=['allmod_v6.6'])
        parser.add_argument('--build_analyzer', action='store_true')
        parser.add_argument('--analyze', type=str, default=None)
        parser.add_argument('--clean_build', action='store_true')
        parser.add_argument('--build_lib', action='store_true')
        parser.add_argument('--build_protobuf', action='store_true')

        self.args = parser.parse_args()

    def _process_args(self):
        if self.args.build_llvm:
            self.components.append(self._build_llvm)
        elif self.args.build_protobuf:
            self.components.append(self._build_protobuf)
        elif self.args.build_qemu:
            self.components.append(self._build_protobuf)
            self.components.append(self._build_lib)
            if not Path(self.env.build_llvm_dir / 'bin/clang').is_file():
                self.components.append(self._build_llvm)
            self.components.append([self._build_qemu, self.args.build_qemu])
        elif self.args.build_linux:
            self.components.append(self._build_llvm)
            self.components.append([self._build_linux, self.args.build_linux])
        elif self.args.build_analyzer:
            self.components.append(self._build_analyzer)
        elif self.args.analyze:
            self.components.append(self._build_analyzer)
            self.components.append(self._analyze)
        elif self.args.build_lib:
            self.components.append(self._build_lib)
        else:
            self.components.append(self._build_llvm)
            self.components.append(self._build_protobuf)
            self.components.append(self._build_lib)
            self.components.append([self._build_qemu, 'all'])
            self.components.append([self._build_linux, 'allmod_v6.6'])
            self.components.append(self._build_analyzer)

    def _run_cmd(self, cmd):
        print('\n[CMD]:', cmd)
        subprocess.run(cmd, shell=True, check=True)

    def _build_protobuf(self):
        os.chdir(self.env.third_party_protobuf_dir)
        utils.run_cmd(f'cmake -DCMAKE_INSTALL_PREFIX={self.env.install_protobuf_dir} '
            f'-B {self.env.build_protobuf_dir} -S cmake -Dprotobuf_BUILD_TESTS=OFF '
            '-DBUILD_SHARED_LIBS=ON')
        utils.run_cmd(f'cmake --build {self.env.build_protobuf_dir} -j`nproc`')
        utils.run_cmd(f'cmake --install {self.env.build_protobuf_dir}')
        os.environ['LD_LIBRARY_PATH'] = f'{self.env.install_protobuf_dir}/lib:{os.environ.get("LD_LIBRARTY_PATH", "")}'

    def _build_qemu(self, build_type):
        print(f'[*]Start to build qemu {build_type}...')

        if build_type == 'all':
            self._build_qemu('upstream')
            self._build_qemu('coverage')
            self._build_qemu('fuzz_with_asan')
            self._build_qemu('fuzz_without_asan')
            return
        elif build_type == 'upstream':
            qemu_build_dir = self.env.build_qemu_upstream_dir
            qemu_install_dir = self.env.install_qemu_upstream_dir
            build_flags = '--enable-debug --enable-sanitizers'
        elif build_type == 'coverage':
            qemu_build_dir = self.env.build_qemu_coverage_dir
            qemu_install_dir = self.env.install_qemu_coverage_dir
            build_flags = ('--enable-fuzzing --extra-cflags="-fprofile-instr-generate -fcoverage-mapping"')
        elif build_type == 'fuzz_with_asan':
            qemu_build_dir = self.env.build_qemu_fuzz_with_asan_dir
            qemu_install_dir = self.env.install_qemu_fuzz_with_asan_dir
            build_flags = '--enable-fuzzing --enable-sanitizers --extra-cflags="-O3"'
        elif build_type == 'fuzz_without_asan':
            qemu_build_dir = self.env.build_qemu_fuzz_without_asan_dir
            qemu_install_dir = self.env.install_qemu_fuzz_without_asan_dir
            build_flags = '--enable-fuzzing --extra-cflags="-O3"'
        else:
            print(f'Wrong qemu build type {build_type}!')
            return

        qemu_source = f'{self.env.third_party_qemu_dir}'
        os.chdir(qemu_source)
        git_version = git.Repo(search_parent_directories=True).head.object.hexsha[:8]

        if build_type != 'upstream':
            utils.run_cmd('git apply ../../config/patch/qemu_truman.patch')

        os.chdir(qemu_build_dir)
        softmmu = []
        for arch in self.env.arch:
            softmmu.append(f'{arch}-softmmu')
        softmmus = ','.join(softmmu)
        utils.run_cmd(f'{qemu_source}/configure --cc=clang '
                f'--target-list={softmmus} {build_flags} '
                f'--prefix={qemu_install_dir} --disable-werror --disable-xen --enable-slirp '
                '--enable-alsa --disable-xkbcommon --enable-opengl --enable-virglrenderer')

        if build_type == 'fuzz_with_asan' or build_type == 'fuzz_without_asan' or build_type == 'coverage':
            threads = '4' if build_type == 'coverage' else '`nproc`'
            utils.run_cmd(f'make -j{threads}')
            utils.run_cmd(f'make install -j{threads}')
            for arch in self.env.arch:
                utils.run_cmd(f'cp {qemu_install_dir}/bin/qemu-truman-{arch} {qemu_install_dir}/bin/qemu-truman-{arch}-{git_version}')
        elif build_type == 'upstream':
            utils.run_cmd(f'bear -- make -j`nproc` qemu-system-x86_64')
            utils.run_cmd(f'make install -j`nproc`')
            utils.run_cmd(f'ln -sf {qemu_build_dir}/compile_commands.json '
                    f'{self.env.third_party_qemu_dir}/compile_commands.json')
        else:
            utils.run_cmd(f'make -j`nproc`')
            utils.run_cmd(f'make install -j`nproc`')

        print(f'[+]Building qemu {build_type} done.')

        os.chdir(qemu_source)
        if build_type != 'upstream':
            utils.run_cmd('git restore .')
            utils.run_cmd('git clean -fdx')

    def _build_lib(self):
        print('[*]Building Libvirtfuzz...')

        os.chdir(self.env.libvirtfuzz_dir)
        cmd = (f'cmake -DCMAKE_INSTALL_PREFIX={self.env.install_libvirtfuzz_dir} '
            f'-B {self.env.build_libvirtfuzz_dir} -DPROTOBUF_DIR={self.env.install_protobuf_dir} '
            f'-DCMAKE_BUILD_TYPE=Release')
        utils.run_cmd(cmd)
        utils.run_cmd(f'cmake --build {self.env.build_libvirtfuzz_dir} -j`nproc`')
        utils.run_cmd(f'cmake --install {self.env.build_libvirtfuzz_dir}')

        utils.run_cmd(f'ln -sf {self.env.build_libvirtfuzz_dir}/compile_commands.json '
                      f'{self.env.libvirtfuzz_dir}/compile_commands.json')

        print('[+]Building libvirtfuzz done.')

    def _build_llvm(self):
        print('[*]Building LLVM...')

        if self.args.clean_build:
            self._run_cmd(f'rm -rf {self.env.build_llvm_dir}')

        os.chdir(self.env.third_party_llvm_dir)
        self._run_cmd('cmake -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=on '
                f'-DCMAKE_INSTALL_PREFIX={self.env.install_llvm_dir} '
                '-DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld" '
                '-DLLVM_ENABLE_RUNTIMES="compiler-rt" '
                f'-DCMAKE_BUILD_TYPE=Release '
                f'-S llvm -B {self.env.build_llvm_dir}')
        self._run_cmd(f'cmake --build {self.env.build_llvm_dir}')
        self._run_cmd(f'cmake --install {self.env.build_llvm_dir}')
        self._run_cmd(f'ln -sf {self.env.build_llvm_dir}/compile_commands.json '
            'compile_commands.json')

        print('[+]Build LLVM done.')

    def _enable_config(self, build_type, out_dir):
        os.chdir(self.env.third_party_linux_dir)
        self._run_cmd(f'make O={out_dir} CC=clang allmodconfig')

        args = types.SimpleNamespace()
        args.config_type = build_type
        args.config_file = f'{out_dir}/.config'
        enable_config = utils.EnableConfig(args)
        enable_config.process()

    def _do_build_linux(self, build_type, out_dir, opt=None):
        if opt != None:
            os.environ['OPT'] = opt
        else:
            os.environ['OPT'] = ''

        if 'allmod' in build_type:
            CC=f'{self.env.scripts_shell_clang}'
            AR=f'{self.env.scripts_shell_ar}'
            LD=f'{self.env.scripts_shell_ld}'
            OBJCOPY=f'{self.env.scripts_shell_objcopy}'
            targets='drivers/ sound/'
        else:
            raise Exception('Wrong build_type!')

        utils.run_cmd(f'make O={out_dir} CC={CC} AR={AR} LD={LD} OBJCOPY={OBJCOPY} '
                f'olddefconfig')
        target_set = set()
        target_set.add('drivers/usb/core/')
        with open(self.env.config_targets) as f:
            targets = yaml.safe_load(f.read())
            for _, devices in targets.items():
                for _, info in devices.items():
                    bitcode = info['bitcode']
                    if 'usb' in bitcode or 'message' in bitcode or 'mmc' in bitcode or 'virtio' in bitcode:
                        target = '/'.join(bitcode.split('/')[:-1]) + '/'
                    else:
                        target = bitcode.replace('.bc', '.o')
                    target_set.add(target)
        targets = ' '.join(target_set)
        utils.run_cmd(f'make O={out_dir} CC={CC} AR={AR} LD={LD} OBJCOPY={OBJCOPY} '
            f'{targets} -j{self.cpu_count}')

        bc_dict_list = [
                {"drivers/virtio/virtio_pci_final.bc": ["drivers/virtio/virtio_pci.bc", "drivers/virtio/virtio_pci_modern_dev.bc"]},
                {"drivers/usb/host/ohci_final.bc": ["drivers/usb/host/ohci-pci.bc", "drivers/usb/host/ohci-hcd.bc", "drivers/usb/core/hcd-pci.bc"]},
                {"drivers/usb/host/ehci_final.bc": ["drivers/usb/host/ehci-pci.bc", "drivers/usb/host/ehci-hcd.bc", "drivers/usb/core/hcd-pci.bc"]},
                {"drivers/usb/host/xhci_final.bc": ["drivers/usb/host/xhci-pci.bc", "drivers/usb/host/xhci-hcd.bc", "drivers/usb/core/hcd-pci.bc"]},
                {"drivers/message/fusion/mptsas_final.bc": ["drivers/message/fusion/mptsas.bc", "drivers/message/fusion/mptbase.bc", "drivers/message/fusion/mptscsih.bc"]},
                {"drivers/mmc/host/sdhci_final.bc": ["drivers/mmc/host/sdhci-pci.bc", "drivers/mmc/host/sdhci.bc"]},
                ]
        for item in bc_dict_list:
            for final, deps in item.items():
                true_final = str(out_dir) + '/' +  final
                true_deps = list(map(lambda x: str(out_dir) + '/' + x, deps))
                utils.run_cmd(f'llvm-link --only-needed -o {true_final} {" ".join(true_deps)}')
                utils.run_cmd(f'llvm-dis {true_final}')

    def _install_module(self):
        self._run_cmd(f'sudo make O={self.env.build_linux_fuzz_dir} modules_install '
            f'INSTALL_MOD_PATH={self.env.image_chroot_dir}')
        os.chdir(self.env.image_dir)
        self._run_cmd(f'sudo rm -rf ./share/lib/modules && '
                'sudo mkdir -p ./share && '
                f'sudo mount -o loop {self.env.image_stretch_img} ./share && '
                f'sudo cp -a {self.env.image_chroot_dir}/lib/modules/ ./share/lib/ && '
                'sudo umount ./share')

    def _build_linux(self, build_type):
        print('[*]Start to build linux...')

        os.chdir(self.env.third_party_linux_dir)
        utils.run_cmd('git apply ../../config/patch/linux.patch')

        allmod_dir = self.env.build_linux_dir / build_type
        if self.args.clean_build:
            self._run_cmd(f'rm -rf {allmod_dir}')
        self._enable_config(build_type, allmod_dir)
        self._do_build_linux(build_type, allmod_dir)

        utils.run_cmd('git restore .')
        utils.run_cmd('git clean -fdx')

        print('[+]Build linux done.')

    def _build_analyzer(self):
        print('[*]Start to build static analyzer...')

        if self.args.clean_build:
            self._run_cmd(f'rm -rf {self.env.build_static_analysis_dir}')

        build_type = 'RelWIthDebInfo'

        if not self.env.svf_lib.is_file():
            os.chdir(self.env.third_party_svf_dir)
            cmd = (f'LLVM_DIR={self.env.install_llvm_dir} ./build.sh')
            utils.run_cmd(cmd)

        if not self.env.z3_lib.is_file():
            os.environ['PYTHON'] = '/usr/bin/python3'
            os.chdir(self.env.third_party_z3_dir)
            cmd = (f'./configure && cd build '
                   f'&& make -j{self.cpu_count} && sudo make install')
            utils.run_cmd(cmd)

        os.chdir(self.env.static_analysis_dir)
        cmd = (f'CC=clang CXX=clang++ cmake -G Ninja '
        f'-B {self.env.build_static_analysis_dir} '
        f'-DCMAKE_INSTALL_PREFIX={self.env.install_static_analysis_dir} '
        f'-DCMAKE_INSTALL_RPATH={self.env.install_static_analysis_lib_dir} '
        f'-DLLVM_DIR={self.env.install_llvm_dir} '
        f'-DPROTOBUF_DIR={self.env.install_protobuf_dir} '
        f'-DSVF_SOURCE_DIR={self.env.third_party_svf_dir} '
        f'-DSVF_LIB={self.env.svf_lib} '
        f'-DZ3_LIB={self.env.z3_lib} '
        f'-DCMAKE_BUILD_TYPE={build_type} ')
        utils.run_cmd(cmd)
        utils.run_cmd(f'cmake --build {self.env.build_static_analysis_dir}')
        utils.run_cmd(f'cmake --install {self.env.build_static_analysis_dir}')

        utils.run_cmd(f'ln -sf {self.env.build_static_analysis_dir}/'
                'compile_commands.json compile_commands.json')

        print('[+]Build static analyzer finished.')

    def _get_path_from_target(self, target):
        with open(self.env.config_targets) as f:
            config = yaml.safe_load(f.read())
            for _, devs in config.items():
                for dev, val in devs.items():
                    if dev != target:
                        continue
                    return val['bitcode']
        raise Exception("Not a valid target!")

    def _analyze(self):
        if self.args.analyze != None:
            target = self.args.analyze
        else:
            raise Exception(f'Please input the target!')

        static_analysis_result = self.env.out_static_analysis_dir / f'{target}.bin'

        target_path = self._get_path_from_target(target)
        if target_path != '':
            target_path = f'{self.env.build_linux_allmod_dir}/{target_path}'
            static_analysis_result.touch()
            start_time = time.time()
            utils.run_cmd(f'script -q -c "opt --disable-output --enable-new-pm=0 '
                f'--load={self.env.build_static_analysis_analyzer_lib} '
                f'-target={target} '
                f'-result={static_analysis_result} '
                f'--dma-analysis-pass {target_path} 2>&1" '
                f'| tee {self.env.out_static_analysis_log}')
            end_time = time.time()
            time_taken = end_time - start_time
            print(f"Analyzing {target} took {time_taken:.2f} seconds")

    def process(self):
        print('[*]Start to setting up...')

        for component in self.components:
            if isinstance(component, list):
                component[0](component[1])
            else:
                component()

        print('[+]Setting up done.')

if __name__ == '__main__':
    setup = Setup()
    setup.process()
