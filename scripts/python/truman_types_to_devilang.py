#!/usr/bin/env python3
"""
JSON to DeviLang Converter
Reads device model JSON files and converts them to human-readable DeviLang format
"""

import json
import os
import sys
import argparse
import random
from pathlib import Path


def parse_device_name_from_path(config_path):
    """
    Parse device name from a config file path.
    e.g., 'config/dbm/ahci-hd.json' -> 'ahci-hd'
          'config/dbm/virtio-blk_dma.json' -> 'virtio-blk'
    """
    filename = Path(config_path).stem  # Remove .json extension
    # Remove _dma suffix if present
    if filename.endswith("_dma"):
        filename = filename[:-4]
    return filename


def find_dma_json_for_config(config_path):
    """
    Given a config file path, find the corresponding DMA JSON if it exists.
    Returns the DMA JSON path or None.
    If config_path is already a _dma.json file, returns None (avoid loading itself).
    """
    config_path = Path(config_path)
    # If this is already a DMA config, don't look for another DMA file
    if config_path.name.endswith("_dma.json"):
        return None
    device_name = parse_device_name_from_path(config_path)
    dma_json = config_path.parent / f"{device_name}_dma.json"
    return dma_json if dma_json.exists() else None


def get_config_files_from_folder(folder_path):
    """
    Get all JSON config files from a folder.
    Excludes _dma.json files (handled by another tool).
    Returns list of config file paths.
    """
    folder = Path(folder_path)
    if not folder.exists():
        raise FileNotFoundError(f"Config folder not found: {folder}")

    all_json_files = sorted(folder.glob("*.json"))

    # Exclude _dma.json files - handled by another tool
    main_configs = [f for f in all_json_files if not f.name.endswith("_dma.json")]

    # Orphan DMA handling commented out - handled by another tool
    # dma_configs = [f for f in all_json_files if f.name.endswith("_dma.json")]
    # main_config_names = {f.stem for f in main_configs}
    # orphan_dma_configs = [
    #     f for f in dma_configs
    #     if f.stem[:-4] not in main_config_names  # Remove "_dma" suffix and check
    # ]
    # if orphan_dma_configs:
    #     orphan_names = [f.name for f in orphan_dma_configs]
    #     print(f"Found orphan DMA configs (no main config): {orphan_names}", file=sys.stderr)

    return main_configs


def regnode_to_expr(node, indent=0):
    """
    Convert a regnode AST to a human-readable expression string.

    Args:
        node: The regnode dictionary
        indent: Current indentation level (for nested expressions)

    Returns:
        String representation of the expression
    """
    if not node:
        return "null"

    node_type = node.get("nodeValueType", "")

    # Leaf nodes
    if node_type == "k_NODE_VALUE_CONSTANT":
        value = node.get("value", 0)
        return f"0x{int(value):x}" if value else "0"

    elif node_type == "k_NODE_VALUE_CALL":
        var_cnt = node.get("varCnt", "?")
        return f"call_{var_cnt}()"

    elif node_type == "k_NODE_VALUE_NUM_TYPE":
        var_cnt = node.get("varCnt", "?")
        return f"num_{var_cnt}"

    elif node_type == "k_NODE_VALUE_COMMON":
        var_cnt = node.get("varCnt", "?")
        return f"var_{var_cnt}"

    elif node_type == "k_NODE_VALUE_ARG":
        children = node.get("children", [])
        if not children:
            return "arg(?)"
        child_exprs = [regnode_to_expr(child, indent) for child in children]
        return f"arg({', '.join(child_exprs)})"

    # Binary operations
    elif node_type in ["k_NODE_VALUE_ADD", "k_NODE_VALUE_AND", "k_NODE_VALUE_OR",
                       "k_NODE_VALUE_SHL", "k_NODE_VALUE_LSHR"]:
        children = node.get("children", [])
        if len(children) != 2:
            return f"{node_type}(?)"

        left = regnode_to_expr(children[0], indent + 1)
        right = regnode_to_expr(children[1], indent + 1)

        op_map = {
            "k_NODE_VALUE_ADD": "+",
            "k_NODE_VALUE_AND": "&",
            "k_NODE_VALUE_OR": "|",
            "k_NODE_VALUE_SHL": "<<",
            "k_NODE_VALUE_LSHR": ">>"
        }
        op = op_map.get(node_type, "?")

        # Add parentheses for nested expressions
        if indent > 0:
            return f"({left} {op} {right})"
        else:
            return f"{left} {op} {right}"

    # Control flow nodes (PHI, SELECT)
    elif node_type in ["k_NODE_VALUE_PHI", "k_NODE_VALUE_SELECT"]:
        children = node.get("children", [])
        if not children:
            return f"{node_type}()"

        child_exprs = [regnode_to_expr(child, indent) for child in children]
        node_name = "phi" if node_type == "k_NODE_VALUE_PHI" else "select"

        return f"{node_name}({', '.join(child_exprs)})"
    else:
        return f"unknown_{node_type}"


def evaluate_regnode(node, common_values=None):
    """
    Evaluate a regnode AST to compute a concrete value.
    Random values are used for CALL/NUM_TYPE/PHI/SELECT nodes.

    Args:
        node: The regnode dictionary
        common_values: Dictionary mapping var_cnt to previously computed values

    Returns:
        Tuple of (result_value, common_values_dict)
    """
    if common_values is None:
        common_values = {}

    if not node:
        return 0, common_values

    node_type = node.get("nodeValueType", "")
    var_cnt = node.get("varCnt")

    # Leaf nodes
    if node_type == "k_NODE_VALUE_CONSTANT":
        result = int(node.get("value", 0))

    elif node_type == "k_NODE_VALUE_CALL":
        # Random value for function calls
        result = random.randint(0, 0xFFFFFFFFFFFFFFFF)

    elif node_type == "k_NODE_VALUE_NUM_TYPE":
        # Random value for numeric types
        result = random.randint(0, 0xFFFFFFFFFFFFFFFF)

    elif node_type == "k_NODE_VALUE_COMMON":
        # Lookup previously computed value
        if var_cnt in common_values:
            result = common_values[var_cnt]
        else:
            raise ValueError(f"No matching var_cnt {var_cnt} found for COMMON node")

    elif node_type == "k_NODE_VALUE_ARG":
        # Select random child
        children = node.get("children", [])
        if not children:
            raise ValueError("ARG node has no children")
        selected_child = random.choice(children)
        result, common_values = evaluate_regnode(selected_child, common_values)

    # Binary operations
    elif node_type == "k_NODE_VALUE_ADD":
        children = node.get("children", [])
        if len(children) != 2:
            raise ValueError("ADD node must have exactly 2 children")
        left, common_values = evaluate_regnode(children[0], common_values)
        right, common_values = evaluate_regnode(children[1], common_values)
        result = (left + right) & 0xFFFFFFFFFFFFFFFF

    elif node_type == "k_NODE_VALUE_AND":
        children = node.get("children", [])
        if len(children) != 2:
            raise ValueError("AND node must have exactly 2 children")
        left, common_values = evaluate_regnode(children[0], common_values)
        right, common_values = evaluate_regnode(children[1], common_values)
        result = left & right

    elif node_type == "k_NODE_VALUE_OR":
        children = node.get("children", [])
        if len(children) != 2:
            raise ValueError("OR node must have exactly 2 children")
        left, common_values = evaluate_regnode(children[0], common_values)
        right, common_values = evaluate_regnode(children[1], common_values)
        result = left | right

    elif node_type == "k_NODE_VALUE_SHL":
        children = node.get("children", [])
        if len(children) != 2:
            raise ValueError("SHL node must have exactly 2 children")
        left, common_values = evaluate_regnode(children[0], common_values)
        right, common_values = evaluate_regnode(children[1], common_values)
        # Limit shift to prevent overflow
        shift_amount = right & 0x3F
        result = (left << shift_amount) & 0xFFFFFFFFFFFFFFFF

    elif node_type == "k_NODE_VALUE_LSHR":
        children = node.get("children", [])
        if len(children) != 2:
            raise ValueError("LSHR node must have exactly 2 children")
        left, common_values = evaluate_regnode(children[0], common_values)
        right, common_values = evaluate_regnode(children[1], common_values)
        # Limit shift to prevent overflow
        shift_amount = right & 0x3F
        result = left >> shift_amount

    # Control flow nodes
    elif node_type in ["k_NODE_VALUE_PHI", "k_NODE_VALUE_SELECT"]:
        children = node.get("children", [])
        if not children:
            raise ValueError(f"{node_type} node has no children")

        # Evaluate all children and randomly select one
        results = []
        for child in children:
            child_result, common_values = evaluate_regnode(child, common_values)
            results.append(child_result)

        result = random.choice(results)

    else:
        raise ValueError(f"Unknown node type: {node_type}")

    # Store result in common_values if var_cnt exists
    if var_cnt is not None:
        common_values[var_cnt] = result

    return result, common_values


def analyze_regnode_complexity(node, depth=0):
    """
    Analyze the complexity of a regnode AST.

    Args:
        node: The regnode dictionary
        depth: Current depth in the tree

    Returns:
        Dictionary with complexity metrics
    """
    if not node:
        return {
            "max_depth": depth,
            "total_nodes": 0,
            "constants": 0,
            "operations": 0,
            "calls": 0,
            "phi_nodes": 0
        }

    node_type = node.get("nodeValueType", "")

    metrics = {
        "max_depth": depth,
        "total_nodes": 1,
        "constants": 1 if node_type == "k_NODE_VALUE_CONSTANT" else 0,
        "operations": 1 if node_type in ["k_NODE_VALUE_ADD", "k_NODE_VALUE_AND",
                                          "k_NODE_VALUE_OR", "k_NODE_VALUE_SHL",
                                          "k_NODE_VALUE_LSHR"] else 0,
        "calls": 1 if node_type in ["k_NODE_VALUE_CALL", "k_NODE_VALUE_NUM_TYPE"] else 0,
        "phi_nodes": 1 if node_type in ["k_NODE_VALUE_PHI", "k_NODE_VALUE_SELECT"] else 0
    }

    # Recursively analyze children
    children = node.get("children", [])
    for child in children:
        child_metrics = analyze_regnode_complexity(child, depth + 1)

        metrics["max_depth"] = max(metrics["max_depth"], child_metrics["max_depth"])
        metrics["total_nodes"] += child_metrics["total_nodes"]
        metrics["constants"] += child_metrics["constants"]
        metrics["operations"] += child_metrics["operations"]
        metrics["calls"] += child_metrics["calls"]
        metrics["phi_nodes"] += child_metrics["phi_nodes"]

    return metrics


def merge_device_models(main_data, dma_data):
    """
    Merge main device model with DMA device model.
    If DMA model exists, add its structures to the main model.
    """
    merged = main_data.copy()

    if dma_data:
        # Add DMA structures to the merged model
        if "structures" in dma_data:
            merged["structures"] = dma_data["structures"]

        # Merge other DMA-specific fields if they exist
        for key in ["dmaNum", "dmaOps"]:
            if key in dma_data:
                merged[key] = dma_data[key]

    return merged


def print_ops(ops):
    """Print operations in DeviLang format"""

    for op in ops:
        op_id = op.get("id", "N/A")

        if "operation" in op:
            # MMIO/PIO operation
            operation = op["operation"]
            op_type = operation.get("type", "unknown")
            rw = operation.get("rw", "?").lower()
            name = operation.get("name", "unknown")
            size = operation.get("size", "?")
            regs = operation.get("reg", [])

            if regs:
                assert(len(regs) >= 1)
                addr = int(regs[0])
            else:
                addr = 0

            regNode = operation.get("regNode", {})
            region_id = operation.get("regionId", 0)

            # Print regNode expression if it's a write operation
            value = None
            if regNode and rw.lower() == 'w':
                expr = regnode_to_expr(regNode)
                # if not expr.startswith('0x'):
                    # print(f"         expr = {expr}")
                # try:
                    # value, _ = evaluate_regnode(regNode)
                # except Exception as e:
                    # print(f"         evaluated = ERROR: {e}")

            # Print basic operation info
            print(f"op op_{op_id} {{")
            if rw == 'w':
                if addr == 0xdeadbeef or addr == 0xdeadc0de:
                    print(f"    mmio {name}_{op_id} {{")
                    print(f"        direction={rw.lower()};")
                    print(f"        region={region_id};")
                    print(f"        address=unknown;")
                    print(f"        size={size};")
                    print(f"        data={expr};")
                    print(f"    }}")
                else:
                    print(f"    mmio {name}_{op_id} {{")
                    print(f"        direction={rw.lower()};")
                    print(f"        region={region_id};")
                    print(f"        address={hex(addr)};")
                    print(f"        size={size};")
                    print(f"        data={expr};")
                    print(f"    }}")
            elif rw == 'r':
                print(f"    mmio {name}_{op_id} {{")
                print(f"        direction={rw.lower()};")
                print(f"        region={region_id};")
                print(f"        address={hex(addr)};")
                print(f"        size={size};")
                print(f"    }}")
            else:
                pass
            print("}\n")


        elif "callee" in op:
            # Function call
            callee = op["callee"]
            func_name = callee.get("name", "unknown")
            num_args = callee.get("numArgs", 0)
            ret_type = callee.get("returnType", "void")

            # print(f"Op[{op_id}] CALL {func_name}(args={num_args}, ret={ret_type})")
            print(f"op op_{op_id} {{")
            print(f"    call {func_name};")
            print("}\n")

        else:
            print(f"Op[{op_id}] UNKNOWN_OP")

    print()


def print_bbs(bb_dict):
    """Print basic blocks in DeviLang format"""
    for bb_key, op_ids in list(bb_dict.items()):
        print(f"bb {bb_key} {{")
        for op_id in op_ids.split():
            print(f"    op op_{op_id};")
        print(f"}}\n")


def print_paths(funcs_dict):
    """Print execution paths from functions in DeviLang format"""
    for func_name, func_data in list(funcs_dict.items()):
        if isinstance(func_data, dict) and "paths" in func_data:
            paths = func_data["paths"]
            if paths:
                for path_id, path_bbs in list(paths.items()):
                    bb_ids = path_bbs.strip().split()
                    print(f"path {func_name}_{path_id} {{")
                    for bb_id in bb_ids:
                        print(f"    bb bb_{bb_id}")
                    print(f"}}\n")


def print_funcs(funcs_dict):
    """Print functions in DeviLang format"""
    for func_name, func_data in list(funcs_dict.items()):
        if isinstance(func_data, dict):
            print(f"func {func_name} {{")
            paths = func_data.get("paths", {})
            if paths:
                for path_id in list(paths.keys()):
                    print(f"    path path_{func_name}_{path_id};")
            print("}\n")


def print_structures(structures):
    """Print DMA structures in DeviLang format"""
    if not structures:
        return

    print("=" * 80)
    print(f"DMA STRUCTURES (Total: {len(structures)})")
    print("=" * 80)

    for struct in structures:
        index = struct.get("index", "N/A")
        name = struct.get("name", "unknown")
        fields = struct.get("fields", [])

        print(f"  Struct[{index}]: {name}")

        for field in fields:
            field_name = field.get("name", "unknown")
            field_type = field.get("field_type", "UNKNOWN")

            field_str = f"    {field_name}: {field_type}"

            if "values" in field:
                field_str += f" = {field['values']}"
            elif "int_mask" in field:
                field_str += f" (mask: {field['int_mask']})"
            elif "int_min" in field and "int_max" in field:
                field_str += f" (range: {field['int_min']}..{field['int_max']})"

            print(field_str)

        print()


def process_config_file(config_path, args):
    """
    Process a single config file and convert to DeviLang format.
    """
    config_path = Path(config_path)
    device_name = parse_device_name_from_path(config_path)
    # dma_json_path = find_dma_json_for_config(config_path)  # Handled by another tool

    print(f"Loading: {config_path}", file=sys.stderr)
    with open(config_path, 'r') as f:
        main_data = json.load(f)

    # DMA JSON handling commented out - handled by another tool
    # dma_data = None
    # if dma_json_path:
    #     print(f"Loading: {dma_json_path}", file=sys.stderr)
    #     with open(dma_json_path, 'r') as f:
    #         dma_data = json.load(f)

    # Merge if DMA data exists
    # device_data = merge_device_models(main_data, dma_data)
    device_data = main_data

    # Check if specific section requested
    print_specific = (args.ops_only or args.bbs_only or args.paths_only or
                     args.funcs_only or args.structs_only)

    if not print_specific or args.ops_only:
        if "ops" in device_data:
            print_ops(device_data["ops"])

    if not print_specific or args.bbs_only:
        if "bb" in device_data:
            print_bbs(device_data["bb"])

    if not print_specific or args.paths_only:
        if "funcs" in device_data:
            print_paths(device_data["funcs"])

    if not print_specific or args.funcs_only:
        if "funcs" in device_data:
            print_funcs(device_data["funcs"])

    # if not print_specific or args.structs_only:
        # if "structures" in device_data:
            # print_structures(device_data["structures"])


def main():
    parser = argparse.ArgumentParser(
        description="Convert device model JSON to DeviLang format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c config/dbm/vmxnet3.json
  %(prog)s -c config/dbm/e1000.json -o custom_output.devilang
  %(prog)s -d config/dbm --output-dir output/
        """
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to a single config JSON file (e.g., config/dbm/ahci-hd.json)"
    )

    parser.add_argument(
        "-d", "--config-dir",
        help="Path to config directory to process all JSON files"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file (default: <device_name>.devilang)"
    )

    parser.add_argument(
        "--output-dir",
        help="Output directory for batch processing (used with -d/--config-dir)"
    )

    parser.add_argument(
        "--ops-only",
        action="store_true",
        help="Print only operations"
    )

    parser.add_argument(
        "--bbs-only",
        action="store_true",
        help="Print only basic blocks"
    )

    parser.add_argument(
        "--paths-only",
        action="store_true",
        help="Print only paths"
    )

    parser.add_argument(
        "--funcs-only",
        action="store_true",
        help="Print only functions"
    )

    parser.add_argument(
        "--structs-only",
        action="store_true",
        help="Print only DMA structures"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.config and not args.config_dir:
        parser.error("Either -c/--config or -d/--config-dir is required")

    if args.config and args.config_dir:
        parser.error("Cannot use both -c/--config and -d/--config-dir")

    if args.output_dir and not args.config_dir:
        parser.error("--output-dir can only be used with -d/--config-dir")

    try:
        if args.config:
            # Process single config file
            config_path = Path(args.config)
            if not config_path.exists():
                raise FileNotFoundError(f"Config file not found: {config_path}")

            # Determine output file
            device_name = parse_device_name_from_path(config_path)
            output_path = args.output if args.output else f"{device_name}.devilang"

            with open(output_path, 'w') as output_file:
                sys.stdout = output_file
                process_config_file(config_path, args)
                sys.stdout = sys.__stdout__

            print(f"Output written to: {output_path}", file=sys.stderr)
        else:
            # Process all config files in folder
            config_files = get_config_files_from_folder(args.config_dir)
            if not config_files:
                print(f"No config files found in: {args.config_dir}", file=sys.stderr)
                sys.exit(1)

            # Determine output directory
            output_dir = Path(args.output_dir) if args.output_dir else Path(".")
            output_dir.mkdir(parents=True, exist_ok=True)

            print(f"Found {len(config_files)} config files", file=sys.stderr)
            for config_path in config_files:
                device_name = parse_device_name_from_path(config_path)
                output_path = output_dir / f"{device_name}.devilang"

                with open(output_path, 'w') as output_file:
                    sys.stdout = output_file
                    process_config_file(config_path, args)
                    sys.stdout = sys.__stdout__

                print(f"Output written to: {output_path}", file=sys.stderr)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
