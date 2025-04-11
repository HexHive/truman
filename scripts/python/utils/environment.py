import os
import types
import multiprocessing
from pathlib import Path

def get_env():
    env = types.SimpleNamespace()
    env.project_name = 'truman'
    env.project_dir = Path(__file__).parent.parent.parent.parent
    env.cpu_count = multiprocessing.cpu_count()
    env.container_name = f'{env.project_name}_container'

    env.third_party_dir = env.project_dir / 'third_party'
    env.third_party_qemu_dir = env.third_party_dir / 'qemu'
    env.third_party_llvm_dir = env.third_party_dir / 'llvm'
    env.third_party_linux_dir = env.third_party_dir / 'linux'
    env.third_party_linux_config_tool = env.third_party_linux_dir / 'scripts/config'
    env.third_party_svf_dir = env.third_party_dir / 'svf'
    env.third_party_z3_dir = env.third_party_dir / 'z3'
    env.third_party_protobuf_dir = env.third_party_dir / 'protobuf'

    env.install_dir = env.project_dir / 'install'
    env.install_qemu_dir = env.install_dir / 'qemu'
    env.install_qemu_normal_with_asan_dir = env.install_qemu_dir / 'normal_with_asan'
    env.install_qemu_fuzz_with_asan_dir = env.install_qemu_dir / 'fuzz_with_asan'
    env.install_qemu_fuzz_without_asan_dir = env.install_qemu_dir / 'fuzz_without_asan'
    env.install_qemu_upstream_dir = env.install_qemu_dir / 'upstream'
    env.install_qemu_coverage_dir = env.install_qemu_dir / 'coverage'
    env.install_qemu_gcov_dir = env.install_qemu_dir / 'gcov'
    env.install_llvm_dir = env.install_dir / 'llvm'
    env.install_static_analysis_dir = env.install_dir / 'static_analysis'
    env.install_static_analysis_lib_dir = env.install_static_analysis_dir / 'lib'
    env.install_svf_dir = env.third_party_svf_dir / 'Release-build' / 'lib'
    env.svf_lib = env.install_svf_dir / 'libSvf.a'
    env.z3_lib = env.third_party_z3_dir / 'build' / 'libz3.so'
    env.install_afl_dir = env.install_dir / 'afl'
    env.install_libvirtfuzz_dir = env.install_dir / 'libvirtfuzz'
    env.install_protobuf_dir = env.install_dir / 'protobuf'

    env.fuzz_binary = 'qemu-fuzz-x86_64'
    env.truman_fuzz_binary = 'qemu-truman-x86_64'
    env.build_dir = env.project_dir / 'build'
    env.build_qemu_dir = env.build_dir / 'qemu'
    env.build_qemu_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_normal_with_asan_dir= env.build_qemu_dir / 'normal_with_asan'
    env.build_qemu_normal_with_asan_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_fuzz_with_asan_dir = env.build_qemu_dir / 'fuzz_with_asan'
    env.build_qemu_fuzz_with_asan_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_fuzz_without_asan_dir = env.build_qemu_dir / 'fuzz_without_asan'
    env.build_qemu_fuzz_without_asan_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_upstream_dir = env.build_qemu_dir / 'upstream'
    env.build_qemu_upstream_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_evaluation_dir = env.build_qemu_dir / 'evaluation'
    env.build_qemu_evaluation_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_fuzz_with_asan_binary = env.install_qemu_fuzz_with_asan_dir / 'bin' / env.fuzz_binary
    env.build_qemu_truman_fuzz_with_asan_binary = env.install_qemu_fuzz_with_asan_dir / 'bin' / env.truman_fuzz_binary
    env.build_qemu_fuzz_without_asan_binary = env.install_qemu_fuzz_without_asan_dir / 'bin' / env.fuzz_binary
    env.build_qemu_truman_fuzz_without_asan_binary = env.install_qemu_fuzz_without_asan_dir / 'bin' / env.truman_fuzz_binary
    env.build_qemu_coverage_dir = env.build_qemu_dir / 'coverage'
    env.build_qemu_coverage_dir.mkdir(parents=True, exist_ok=True)
    env.build_qemu_coverage_binary = env.install_qemu_coverage_dir / 'bin' / env.fuzz_binary
    env.build_qemu_truman_coverage_binary = env.install_qemu_coverage_dir / 'bin' / env.truman_fuzz_binary
    env.build_qemu_coverage_binary_x86 = env.install_qemu_coverage_dir / 'bin' / 'qemu-system-x86_64'
    env.build_llvm_dir = env.build_dir / 'llvm'
    env.build_llvm_dir.mkdir(parents=True, exist_ok=True)
    env.build_linux_dir = env.build_dir / 'linux'
    env.build_linux_allmod_dir = env.build_linux_dir / 'allmod_v6.6'
    env.build_linux_fuzz_dir = env.build_linux_dir / 'fuzz'
    env.build_static_analysis_dir = env.build_dir / 'static_analysis'
    env.build_static_analysis_analyzer_lib = env.build_static_analysis_dir / 'Analyzer/libAnalyzer.so'
    env.build_static_analysis_dma_pass = env.build_static_analysis_dir / 'DMAPass/libDMAPass.so'
    env.build_static_analysis_io_pass = env.build_static_analysis_dir / 'DMAPass/libIOPass.so'
    env.build_libvirtfuzz_dir = env.build_dir / 'libvirtfuzz'
    env.build_protobuf_dir = env.build_dir / 'protobuf'

    env.config_dir = env.project_dir / 'config'
    env.config_linux_dir = env.config_dir / 'linux'
    env.config_linux_enable_config = env.config_linux_dir / 'enable_config.json'
    env.config_fuzz_dir = env.config_dir / 'fuzz'
    env.config_fuzz_dict = env.config_fuzz_dir / 'dict'
    env.config_targets = env.config_dir / 'targets.yaml'
    env.config_dbm_dir = env.config_dir / 'dbm'

    env.scripts_dir = env.project_dir / 'scripts'
    env.scripts_shell_dir = env.scripts_dir / 'shell'
    env.scripts_shell_clang = env.scripts_shell_dir / 'clang.sh'
    env.scripts_shell_ar = env.scripts_shell_dir / 'ar.sh'
    env.scripts_shell_ld = env.scripts_shell_dir / 'ld.sh'
    env.scripts_shell_objcopy = env.scripts_shell_dir / 'objcopy.sh'
    env.scripts_python_dir = env.scripts_dir / 'python'
    env.scirpts_setup = env.scripts_python_dir / 'setup.py'

    env.out_dir = env.project_dir / 'out'
    env.out_fuzz_dir = env.out_dir / 'fuzz'
    env.out_static_analysis_dir = env.out_dir / 'static_analysis'
    env.out_static_analysis_dir.mkdir(parents=True, exist_ok=True)
    env.out_static_analysis_log = env.out_static_analysis_dir / 'analysis.log'

    env.static_analysis_dir = env.project_dir / 'static_analysis'

    env.tmp_dir = Path('/tmp/truman')
    env.tmp_dir.mkdir(parents=True, exist_ok=True)

    env.libvirtfuzz_dir = env.project_dir / 'libvirtfuzz'

    os.environ['PATH'] = f'{env.install_qemu_dir}/bin' + os.pathsep + os.environ['PATH']
    os.environ['PATH'] = f'{env.install_llvm_dir}/bin' + os.pathsep + os.environ['PATH']
    os.environ['LD_LIBRARY_PATH'] = f'{env.install_libvirtfuzz_dir}/lib:{os.environ.get("LD_LIBRARY_PATH", "")}'
    os.environ['LD_LIBRARY_PATH'] = f'{env.install_protobuf_dir}/lib:{os.environ.get("LD_LIBRARY_PATH", "")}'

    env.arch = ['x86_64']

    env.targets = ['igb', 'vmxnet3', 'fdc-isa', 'sdhci-v3', 'e1000e', 'xhci', 'ehci', 'nvme',
                   'virtio-net-pci-slirp', 'virtio-blk', 'virtio-balloon', 'virtio-crypto-pci', 'virtio-gpu', 'virtio-scsi',
                   'virtio-iommu', 'virtio-mem-pci', 'virtio-sound',
                   'ac97', 'cs4231a', 'es1370', 'intel-hda', 'sb16', 'ahci-hd', 'e1000', 'i82550', 'pcnet', 'rtl8139', 'ati-vga', 'cirrus-vga', 'ohci']

    return env
