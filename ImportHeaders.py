from binaryninja import *
import argparse
import os
import sys

def parse_header(bv: BinaryView, header_path: str, options: List[str], include_dirs: List[str]) -> bool:
	with open(header_path) as header_str:
		try:
			result = bv.parse_types_from_string(header_str.read(), options, include_dirs)
		except SyntaxError:
			print(f"[!] Unable to parse [{header_path}]")
			return False

		# add types
		for type in result.types:
			bv.define_user_type(type, result.types[type])

		# add functions
		for func in result.functions:
			# Find func in bv
			func_sym = bv.get_symbols_by_name(func.name[0])
			if len(func_sym) == 0:
				func_sym = bv.get_symbols_by_name(f"_{func.name[0]}")
				if len(func_sym) == 0:
					print(f"[!] Unable to find {func.name[0]}")
					break

			func_sym = func_sym[0]
			bv_func = bv.get_function_at(func_sym.address)
			if bv_func is None:
				break

			bv.define_imported_function(func_sym, bv_func, result.functions[func])

		# add variables
	return True

#include_dirs = get_sys_include_dirs()
parser = argparse.ArgumentParser(prog="HeadlessHeaders", description="Headless C/C++ header parser for binary ninja", epilog="Author: @SmoothHacker")
parser.add_argument('-bv', '--binaryview', dest="user_binaryview")
parser.add_argument('-i', '--include-dirs', dest="include_dirs", default=[""])
parser.add_argument('--options', dest="options", default=[""])
parser.add_argument('headers', nargs='+')

args = parser.parse_args()

bv = open_view(os.path.abspath(args.user_binaryview))
include_dirs = args.include_dirs.split(',')
include_dirs = [os.path.abspath(x) for x in include_dirs]

for header in args.headers:
	parse_header(bv, header, args.options, include_dirs)

print(f"[*] Saving to -> {os.path.basename(bv.file.filename)}.bndb")
bv.create_database(f"{os.path.basename(bv.file.filename)}.bndb")