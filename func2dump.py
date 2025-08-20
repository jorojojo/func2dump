#!/bin/python
import argparse
import re
import sys
from subprocess import check_output, CalledProcessError


def parse_objdump(path_to_bin: str) -> dict[str, str] | None:
    # -dC (dissasemble/demangle) makes it easier for parsing
    cmd = f"objdump -dC {path_to_bin}"
    output = ""

    try:
        output = check_output(args=cmd.split(" ")).decode("utf-8")
    except (CalledProcessError, FileNotFoundError) as e:
        print(
            f"ERROR: could not execute objdump. Please check the path or installation: {e}"
        )
        return None

    pattern = re.compile(r"([A-Za-z0-9]+) <([A-Za-z0-9]+)(\(\))?>:")

    function_addr_map = {}

    for s in output.splitlines():
        match = pattern.match(s)
        if match:
            function_addr_map[match.group(2)] = match.group(1)

    return function_addr_map


def get_function_addresses(
    function_map: dict[str, str] | None, functions: list[str]
) -> dict[str, str] | None:

    if not function_map:
        return None

    found_addresses = {func: function_map.get(func) for func in functions}

    unfound_functions = [func for func, addr in found_addresses.items() if addr is None]

    if unfound_functions:
        print(
            "ERROR: Could not find a valid address for the following function(s), please ensure the naming is correct:"
        )
        for func in unfound_functions:
            print(f"- {func}")
        return None

    return found_addresses


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Func2Dump: output function /addresses in a compiled C/C++ binary"
    )
    parser.add_argument(
        "-p", "--path", help="Path to the compiled C/C++ binary", required=True
    )
    parser.add_argument(
        "-f",
        "--functions",
        nargs="+",
        help="Function(s) addresse(es) to print",
        required=True,
    )
    parser.add_argument(
        "-d",
        "--diff-offset",
        help="Optionally diff the byte offset between two functions of interest, diffs first two functions passed in",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()

    if args.diff_offset and len(args.functions) != 2:
        parser.error("The --diff-offset option requires exactly two function names.")

    objdump_output = parse_objdump(args.path)
    if not objdump_output:
        sys.exit(1)

    function_addresses = get_function_addresses(objdump_output, args.functions)
    if not function_addresses:
        sys.exit(1)

    for func, addr in function_addresses.items():
        print(f"Found '{func}' at 0x{addr}")

    if args.diff_offset:
        func1, func2 = args.functions[0], args.functions[1]
        addr1, addr2 = function_addresses[func1], function_addresses[func2]
        try:
            print(f"Byte offset: {abs(int(addr1, 16) - int(addr2, 16))}")
        except ValueError as err:
            print(f"ERROR: Could not calculate offset: {err}")
