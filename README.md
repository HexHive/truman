# Truman

> **Implementation of the paper:**  
> *"Truman: Constructing Device Behavior Models from OS Drivers to Fuzz Virtual Devices"*  
> Presented at the 32nd Annual Network and Distributed System Security Symposium (NDSS 2025)

## Overview

This repository provides the source code associated with our paper, which presents a new method for fuzzing virtual devices. Truman extracts dependencies from open-source OS drivers to construct device behavior models (DBMs) for virtual device fuzzing, regardless of whether target virtual devices are open-source or binaries. The DBM includes inter- and intra-message dependencies and fine-grained state dependency of virtual device messages. Based on the DBM, Truman generates and mutates quality seeds that satisfy the dependencies encoded in the DBM.

## Usage

**Tested on:** `Ubuntu 24.04.2`

### 1. Build and Run the Docker Environment

```
python3 /path/to/truman/scripts/python/docker.py --build
python3 /path/to/truman/scripts/python/docker.py --run
```

### 2. Set Up the Environment

```
python3 /path/to/truman/scripts/python/setup.py
```

### 3. Generate the Fuzzing Command Line

```
python3 /path/to/truman/scripts/python/fuzz_cmd.py
```

### 4. Start Fuzzing a Virtual Device

```
python3 /path/to/truman/scripts/python/fuzz.py -e --fork -t virtio-sound --tool truman
```

Results will be saved in a directory like:  `/path/to/truman/out/fuzz/evaluation_0101`

### 5. Collect Coverage

```
python3 /path/to/truman/scripts/python/collect_coverage.py \
  --base /path/to/truman/out/fuzz/evaluation_0101 \
  --filter 0101 \
  -w 4
```

## Advanced Options

### Fuzzing Options

```
python3 /path/to/truman/scripts/python/fuzz.py [OPTIONS]
--asan              Enable AddressSanitizer  
--fork              Use fork-based fuzzing  
--tool              Select the fuzzing tool (truman or morphuzz)  
-t, --target        Specify the target virtual device  
-e, --evaluation    Enable evaluation mode  
-d, --debug         Enable debug output
```

### Coverage Collection

```
python3 /path/to/truman/scripts/python/collect_coverage.py [OPTIONS]
--base              Base directory of evaluation results  
--filter            Suffix to match the evaluation subdirectory  
-w, --workers       Number of parallel worker processes  
-d, --debug         Enable debug output
```

## Citation

If you use Truman in your research, please cite our paper:

```
@inproceedings{DBLP:conf/ndss/Ma0LYT0P25,
  author       = {Zheyu Ma and
                  Qiang Liu and
                  Zheming Li and
                  Tingting Yin and
                  Wende Tan and
                  Chao Zhang and
                  Mathias Payer},
  title        = {Truman: Constructing Device Behavior Models from {OS} Drivers to Fuzz
                  Virtual Devices},
  booktitle    = {32nd Annual Network and Distributed System Security Symposium, {NDSS}
                  2025, San Diego, California, USA, February 24-28, 2025},
  publisher    = {The Internet Society},
  year         = {2025},
  url          = {https://www.ndss-symposium.org/ndss-paper/truman-constructing-device-behavior-models-from-os-drivers-to-fuzz-virtual-devices/},
  timestamp    = {Wed, 19 Mar 2025 15:12:36 +0100},
  biburl       = {https://dblp.org/rec/conf/ndss/Ma0LYT0P25.bib},
  bibsource    = {dblp computer science bibliography, https://dblp.org}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
