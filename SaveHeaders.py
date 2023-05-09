from binaryninja import *
import argparse
import os
import sys

SYSNAME = os.uname().sysname

def get_sys_include_dirs() -> List[str]:
	if SYSNAME == "Darwin":
		include_dirs = ["/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/14.0.3/include", "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include", "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include", "/usr/local/include"]
		# os.popen("clang -Wp,-v -E -")
		# Look at how to read stderr from a subprocess
		return include_dirs
	else:
		print(f"[!] Unsupported OS: {SYSNAME}")
		sys.exit(0)


def parse_header(bv: BinaryView, header_path: str, options: List[str], include_dirs: List[str]) -> bool:
	include_dirs += get_sys_include_dirs()
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

include_dirs = get_sys_include_dirs()
bv = open_view("./megatest/build/megatest")
parse_header(bv, "./megatest/src/store.h", [], include_dirs)
parse_header(bv, "./megatest/src/megatest.h", [], include_dirs)

print(f"[*] Saving to -> {os.path.basename(bv.file.filename)}.bndb")
bv.create_database(f"{os.path.basename(bv.file.filename)}.bndb")