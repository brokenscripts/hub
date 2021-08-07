#!/usr/bin/python3

import lief
import datetime
import os
import sys
import hashlib
import argparse
import traceback
import time
try:
    import magic
    magicInstalled = True
except ImportError:
    print("python-magic not installed.. skipping magic check")
    magicInstalled = False
try:
    import yara
    yaraInstalled = True
except ImportError:
    print("yara-python is not installed.. skipping all yara sections")
    yaraInstalled = False

"""
Source: https://github.com/lief-project/LIEF/blob/e875a8ffa279ddced72ea2f8add8e569791cf115/examples/python/pe_reader.py
Tested on Python 3.7.3
Version: 0.4-20210404

BEFORE Installing yara, you MUST have libssl-dev installed otherwise there will be lots of issues.  
PIP builds from source and if libssl-dev isn't present, it compiles yara without that support.  That causes a major issue.
"""

def parse_args():
    """Clean way to parse args instead of lumping inside main"""
    parser = argparse.ArgumentParser()
    parser.add_argument("binary_file")

    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',   # Set a true flag if used.  Store in show_all variable
            help='Show all informations')
    
    parser.add_argument('-y', '--yara-rules',
            action='store', dest='yara_rules_path',   # Set a true flag if used.  Store in show_all variable
            help='Specify a yara-rules directory')

    args = parser.parse_args()

    print("[*] Input arguments: ")
    for arg in vars(args):
        print("  [!] {} is {}".format(arg, getattr(args, arg)))

    return args


class exceptions_handler(object):
    func = None

    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions         = exceptions
        self.on_except_callback = on_except_callback

    def __call__(self, *args, **kwargs):
        if self.func is None:
            self.func = args[0]
            return self
        try:
            return self.func(*args, **kwargs)
        except self.exceptions as e:
            if self.on_except_callback is not None:
                self.on_except_callback(e)
            else:
                print("-" * 60)
                print("Exception in {}: {}".format(self.func.__name__, e))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                print("-" * 60)

class ELF:
    def __init__(self, args):
        """
        Store the lief.ELF.parse object as liefBinary.  For use with LIEF
        Store the raw bytes read in as rawBinary.  For use with YARA / raw byte matching
        """
        try:
            lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR) # Only interested when things go really bad
        except:
            pass
        try:
            # Create the liefBinary (Lief) object
            self.liefBinary = lief.ELF.parse(args.binary_file)
            # Creat the rawBinary object
            with open(args.binary_file, 'rb') as f:
                self.rawBinary = f.read()
        except lief.exception as e:
            print(e)
            sys.exit(1)
        self.md5 = hashlib.md5(self.rawBinary).hexdigest()
        self.sha1 = hashlib.sha1(self.rawBinary).hexdigest()
        self.sha256 = hashlib.sha256(self.rawBinary).hexdigest()
        self.size = os.path.getsize(args.binary_file)
        if magicInstalled:
            self.magic = magic.from_file(args.binary_file)
        self.pie = self.liefBinary.is_pie
        self.nx = self.liefBinary.has_nx
        self.header = self.liefBinary.header
        self.identity = self.header.identity


    #@exceptions_handler(Exception)
    def print_information(self):

        print("# Information  \n")
        print("```")
        format_str = "{:<30} {:<30}"
        format_dec = "{:<30} {:<30d}"
        format_hex = "{:<30} 0x{:<28x}"
        format_ide = "{:<30} {:<02x} {:<02x} {:<02x} {:<02x}"

        eflags_str = ""
        if self.header.machine_type == lief.ELF.ARCH.ARM:
            eflags_str = " - ".join([str(s).split(".")[-1] for s in self.header.arm_flags_list])

        if self.header.machine_type in [lief.ELF.ARCH.MIPS, lief.ELF.ARCH.MIPS_RS3_LE, lief.ELF.ARCH.MIPS_X]:
            eflags_str = " - ".join([str(s).split(".")[-1] for s in self.header.mips_flags_list])

        if self.header.machine_type == lief.ELF.ARCH.PPC64:
            eflags_str = " - ".join([str(s).split(".")[-1] for s in self.header.ppc64_flags_list])

        if self.header.machine_type == lief.ELF.ARCH.HEXAGON:
            eflags_str = " - ".join([str(s).split(".")[-1] for s in self.header.hexagon_flags_list])

        print(format_str.format("Name:",                self.liefBinary.name))
        print(format_str.format("File Size:",           self.size))
        if magicInstalled:
            print(format_str.format("Magic:",               self.magic))
        else:
            print(format_ide.format("Magic:",                 self.identity[0], self.identity[1], self.identity[2], self.identity[3]))
        print(format_hex.format("Virtual size:",        self.liefBinary.virtual_size))
        print(format_str.format("MD5:",                 self.md5))
        print(format_str.format("SHA1:",                self.sha1))
        print(format_str.format("SHA256:",              self.sha256))
        print(format_str.format("PIE:",                 str(self.pie)))
        print(format_str.format("NX:",                  str(self.nx)))
        print(format_str.format("Class:",                 str(self.header.identity_class).split(".")[-1]))
        print(format_str.format("Endianness:",            str(self.header.identity_data).split(".")[-1]))
        print(format_str.format("Version:",               str(self.header.identity_version).split(".")[-1]))
        print(format_str.format("OS/ABI:",                str(self.header.identity_os_abi).split(".")[-1]))
        print(format_dec.format("ABI Version:",           self.header.identity_abi_version))
        print(format_str.format("File Type:",             str(self.header.file_type).split(".")[-1]))
        print(format_str.format("Machine Type:",          str(self.header.machine_type).split(".")[-1]))
        print(format_str.format("Object File Version:",   str(self.header.object_file_version).split(".")[-1]))
        print(format_hex.format("Entry Point:",           self.header.entrypoint))
        print(format_hex.format("Program Header Offset:", self.header.program_header_offset))
        print(format_hex.format("Section Header Offset:", self.header.section_header_offset))
        print(format_hex.format("Processor flags:",       self.header.processor_flag) + eflags_str)
        print(format_dec.format("Header Size:",           self.header.header_size))
        print(format_dec.format("Program Header Size:",   self.header.program_header_size))
        print(format_dec.format("Section Header Size:",   self.header.section_header_size))
        print(format_dec.format("Number of segments:",    self.header.numberof_segments))
        print(format_dec.format("Number of sections:",    self.header.numberof_sections))
        print("```")
        print("")


    def print_sections(self):
        sections = self.liefBinary.sections

        print("\n# Sections  \n")
        print("```")

        if len(sections) > 0:
            f_title = "|{:<30} | {:<12}| {:<17}| {:<12}| {:<10}| {:<8}| {:<8}|"
            f_value = "|{:<30} | {:<12}| 0x{:<14x} | 0x{:<10x}| 0x{:<8x}| {:<8.2f}| {:<10}"
            print(f_title.format("Name", "Type", "Virtual address", "File offset", "Size", "Entropy", "Segment(s)"))

            for section in sections:
                segments_str = " - ".join([str(s.type).split(".")[-1] for s in section.segments])
                print(f_value.format(
                    section.name,
                    str(section.type).split(".")[-1],
                    section.virtual_address,
                    section.file_offset,
                    section.size,
                    abs(section.entropy),
                    segments_str))
            print("```")
            print("")
        else:
            print("No sections\n")
            print("```")



    def print_import_name_only(self):
        symbols = self.liefBinary.imported_symbols
        if len(symbols) > 0:
            print("\n# Import Summary \n")
            print("```")
            import_list = []
            for i in symbols:
                if i.imported:
                    import_list.append(i.name)
            print(sorted(import_list))
            print("```")
        else:
            print("No imported symbols")
        print("")




class PE:
    def __init__(self, args):
        """
        Store the lief.PE.parse object as liefBinary.  For use with LIEF
        Store the raw bytes read in as rawBinary.  For use with YARA / raw byte matching
        """
        try:
            lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR) # Only interested when things go really bad
        except:
            pass
        try:
            # Create the liefBinary (Lief) object
            self.liefBinary = lief.PE.parse(args.binary_file)
            # Creat the rawBinary object
            with open(args.binary_file, 'rb') as f:
                self.rawBinary = f.read()
        except lief.exception as e:
            print(e)
            sys.exit(1)
        self.md5 = hashlib.md5(self.rawBinary).hexdigest()
        self.sha1 = hashlib.sha1(self.rawBinary).hexdigest()
        self.sha256 = hashlib.sha256(self.rawBinary).hexdigest()
        self.size = os.path.getsize(args.binary_file)
        if magicInstalled:
            self.magic = magic.from_file(args.binary_file)
        self.pie = self.liefBinary.is_pie
        self.nx = self.liefBinary.has_nx
        self.dep = self.liefBinary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT)
        self.aslr = self.liefBinary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
        self.cfg = self.liefBinary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF)
        self.noseh = self.liefBinary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH)
        self.tls = self.liefBinary.has_tls
        self.dt = datetime.datetime.fromtimestamp(self.liefBinary.header.time_date_stamps, datetime.timezone.utc).strftime('%a %d %b %Y %X %p %Z')


    

    #@exceptions_handler(Exception)
    def print_information(self):
        print("# Information  \n")
        print("```")
        format_str = "{:<30} {:<30}"
        format_hex = "{:<30} 0x{:<28x}"
        print(format_str.format("Name:",                self.liefBinary.name))
        print(format_str.format("File Size:",           self.size))
        print(format_str.format("Time Date Stamp:",     self.dt))
        if magicInstalled:
            print(format_str.format("Magic:",               self.magic))
        print(format_hex.format("Virtual size:",        self.liefBinary.virtual_size))
        print(format_str.format("MD5:",                 self.md5))
        print(format_str.format("SHA1:",                self.sha1))
        print(format_str.format("SHA256:",              self.sha256))
        print(format_str.format("IMPHASH:",             lief.PE.get_imphash(self.liefBinary)))
        print(format_str.format("PIE:",                 str(self.pie)))
        print(format_str.format("NX:",                  str(self.nx)))
        print(format_str.format("DEP:",                 str(self.dep)))
        print(format_str.format("ASLR:",                str(self.aslr)))
        print(format_str.format("CFG:",                 str(self.cfg)))
        if self.liefBinary.has_configuration:
            print(format_str.format("/GS:",             str(self.liefBinary.load_configuration.security_cookie != 0)))
        else:
            print(format_str.format("/GS:",             str("False")))
        print(format_str.format("NOSEH:",               str(self.noseh)))
        print(format_str.format("TLS:",                 str(self.tls)))
        print("```")
        print("")


    def print_version_only(self):
        if self.liefBinary.has_resources and self.liefBinary.resources_manager.has_version:
            self.peVer = self.liefBinary.resources_manager.version.string_file_info
            print("\n# File Info/Version:  \n")
            print(self.peVer)
            print("")


    def print_sections(self):
        sections = self.liefBinary.sections

        print("\n# Sections  \n")
        print("```")
        f_title = "| {:<10} | {:<16} | {:<16} | {:<18} | {:<16} | {:<9} | {:<9}"
        f_value = "| {:<10} | 0x{:<14x} | 0x{:<14x} | 0x{:<16x} | 0x{:<14x} | {:<9.2f} | {:<9}"
        print(f_title.format("Name", "Offset", "Size", "Virtual Address", "Virtual size", "Entropy", "Flags"))

        for section in sections:
            flags = ""
            for flag in section.characteristics_lists:
                flags += str(flag).split(".")[-1] + " "
            print(f_value.format(section.name, section.offset, section.size, section.virtual_address, section.virtual_size, section.entropy, flags))
        print("```")
        print("")

    
    def print_import_name_only(self):
        print("\n# Import Summary \n")
        print("```")
        import_list = []
        for i in self.liefBinary.imports:
            import_list.append(i.name)
        print(sorted(import_list))
        print("```")
        print("")


    def print_header(self):
        dos_header       = self.liefBinary.dos_header
        header           = self.liefBinary.header
        optional_header  = self.liefBinary.optional_header

        format_str = "{:<33} {:<30}"
        format_hex = "{:<33} 0x{:<28x}"
        format_dec = "{:<33} {:<30d}"

        print("\n# DOS Header  \n")
        print(format_str.format("  Magic:",                       hex(dos_header.magic)))
        print(format_dec.format("  Used bytes in the last page:", dos_header.used_bytes_in_the_last_page))
        print(format_dec.format("  File size in pages:",          dos_header.file_size_in_pages))
        print(format_dec.format("  Number of relocations:",       dos_header.numberof_relocation))
        print(format_dec.format("  Header size in paragraphs:",   dos_header.header_size_in_paragraphs))
        print(format_dec.format("  Minimum extra paragraphs:",    dos_header.minimum_extra_paragraphs))
        print(format_dec.format("  Maximum extra paragraphs",     dos_header.maximum_extra_paragraphs))
        print(format_dec.format("  Initial relative SS",          dos_header.initial_relative_ss))
        print(format_hex.format("  Initial SP:",                  dos_header.initial_sp))
        print(format_hex.format("  Checksum:",                    dos_header.checksum))
        print(format_dec.format("  Initial IP:",                  dos_header.initial_ip))
        print(format_dec.format("  Initial CS:",                  dos_header.initial_relative_cs))
        print(format_hex.format("  Address of relocation table:", dos_header.addressof_relocation_table))
        print(format_dec.format("  Overlay number:",              dos_header.overlay_number))
        print(format_dec.format("  OEM ID:",                      dos_header.oem_id))
        print(format_dec.format("  OEM information",              dos_header.oem_info))
        print(format_hex.format("  Address of optional header:",  dos_header.addressof_new_exeheader))
        print("")

        print("\n## Header  \n")

        char_str = " - ".join([str(chara).split(".")[-1] for chara in header.characteristics_list])

        print(format_str.format("  Signature:",               "".join(map(chr, header.signature))))
        print(format_str.format("  Machine:",                 str(header.machine)))
        print(format_dec.format("  Number of sections:",      header.numberof_sections))
        print(format_dec.format("  Time Date stamp:",         header.time_date_stamps))
        print(format_dec.format("  Pointer to symbols:",      header.pointerto_symbol_table))
        print(format_dec.format("  Number of symbols:",       header.numberof_symbols))
        print(format_dec.format("  Size of optional header:", header.sizeof_optional_header))
        print(format_str.format("  Characteristics:",         char_str))
        print("")


        dll_char_str = " - ".join([str(chara).split(".")[-1] for chara in optional_header.dll_characteristics_lists])
        subsystem_str = str(optional_header.subsystem).split(".")[-1]
        print("\n## Optional Header  \n")
        magic = "PE32" if optional_header.magic == lief.PE.PE_TYPE.PE32 else "PE64"
        print(format_str.format("  Magic:",                          magic))
        print(format_dec.format("  Major linker version:",           optional_header.major_linker_version))
        print(format_dec.format("  Minor linker version:",           optional_header.minor_linker_version))
        print(format_dec.format("  Size of code:",                   optional_header.sizeof_code))
        print(format_dec.format("  Size of initialized data:",       optional_header.sizeof_initialized_data))
        print(format_dec.format("  Size of uninitialized data:",     optional_header.sizeof_uninitialized_data))
        print(format_hex.format("  Entry point:",                    optional_header.addressof_entrypoint))
        print(format_hex.format("  Base of code:",                   optional_header.baseof_code))
        if magic == "PE32":
            print(format_hex.format("  Base of data",                optional_header.baseof_data))
        print(format_hex.format("  Image base:",                     optional_header.imagebase))
        print(format_hex.format("  Section alignment:",              optional_header.section_alignment))
        print(format_hex.format("  File alignment:",                 optional_header.file_alignment))
        print(format_dec.format("  Major operating system version:", optional_header.major_operating_system_version))
        print(format_dec.format("  Minor operating system version:", optional_header.minor_operating_system_version))
        print(format_dec.format("  Major image version:",            optional_header.major_image_version))
        print(format_dec.format("  Minor image version:",            optional_header.minor_image_version))
        print(format_dec.format("  Major subsystem version:",        optional_header.major_subsystem_version))
        print(format_dec.format("  Minor subsystem version:",        optional_header.minor_subsystem_version))
        print(format_dec.format("  WIN32 version value:",            optional_header.win32_version_value))
        print(format_hex.format("  Size of image:",                  optional_header.sizeof_image))
        print(format_hex.format("  Size of headers:",                optional_header.sizeof_headers))
        print(format_hex.format("  Checksum:",                       optional_header.checksum))
        print(format_str.format("  Subsystem:",                      subsystem_str))
        print(format_str.format("  DLL Characteristics:",            dll_char_str))
        print(format_hex.format("  Size of stack reserve:",          optional_header.sizeof_stack_reserve))
        print(format_hex.format("  Size of stack commit:",           optional_header.sizeof_stack_commit))
        print(format_hex.format("  Size of heap reserve:",           optional_header.sizeof_heap_reserve))
        print(format_hex.format("  Size of heap commit:",            optional_header.sizeof_heap_commit))
        print(format_dec.format("  Loader flags:",                   optional_header.loader_flags))
        print(format_dec.format("  Number of RVA and size:",         optional_header.numberof_rva_and_size))
        print("")


    def print_data_directories(self):
        data_directories = self.liefBinary.data_directories

        print("\n# Data Directories  \n")
        f_title = "| {:<24} | {:<10} | {:<10} | {:<8} |"
        f_value = "| {:<24} | 0x{:<8x} | 0x{:<8x} | {:<8} |"
        print(f_title.format("Type", "RVA", "Size", "Section"))

        for directory in data_directories:
            section_name = directory.section.name if directory.has_section else ""
            print(f_value.format(str(directory.type).split('.')[-1], directory.rva, directory.size, section_name))
        print("")


    def print_symbols(self):
        symbols = self.liefBinary.symbols
        if len(symbols) > 0:
            print("# Symbols  ")
            f_title = "|{:<20} | {:<10} | {:<8} | {:<8} | {:<8} | {:<13} |"
            f_value = u"|{:<20} | 0x{:<8x} | {:<14} | {:<10} | {:<12} | {:<13} |"

            print(f_title.format("Name", "Value", "Section number", "Basic type", "Complex type", "Storage class"))
            for symbol in symbols:
                section_nb_str = ""
                if symbol.section_number <= 0:
                    section_nb_str = str(PE.SYMBOL_SECTION_NUMBER(symbol.section_number)).split(".")[-1]
                else:
                    try:
                        section_nb_str = symbol.section.name
                    except Exception:
                        section_nb_str = "section<{:d}>".format(symbol.section_number)


                print(f_value.format(
                    symbol.name[:20],
                    symbol.value,
                    section_nb_str,
                    str(symbol.base_type).split(".")[-1],
                    str(symbol.complex_type).split(".")[-1],
                    str(symbol.storage_class).split(".")[-1]))


    def print_imports(self, resolve=False):
        print("\n# Imports  ")
        imports = self.liefBinary.imports

        for import_ in imports:
            if resolve:
                import_ = lief.PE.resolve_ordinals(import_)

            print(f"\n## {import_.name}\n")
            entries = import_.entries
            f_value = "  {:<60} 0x{:<14x} 0x{:<14x} 0x{:<16x}"
            print(f"{'  Name:':<60} {'  IAT Addr:':<14} {'    IAT Value:':<14} {'      Hint:':<14}")
            for entry in entries:
                if entry.name:
                    print(f_value.format(entry.name, entry.iat_address, entry.iat_value, entry.hint))
                else:
                    print(f"{'  ---':<60} {'  ---':<14} {'    ---':<14} {'      ---':<14}")
        print("")


    def print_tls(self):
        format_str = "{:<33} {:<30}"
        format_hex = "{:<33} 0x{:<28x}"

        print("\n# TLS  \n")
        tls = self.liefBinary.tls
        callbacks = tls.callbacks
        print(format_hex.format("Address of callbacks:", tls.addressof_callbacks))
        if len(callbacks) > 0:
            print("Callbacks:")
            for callback in callbacks:
                print("  " + hex(callback))

        print(format_hex.format("Address of index:",  tls.addressof_index))
        print(format_hex.format("Size of zero fill:", tls.sizeof_zero_fill))
        print("{:<33} 0x{:<10x} 0x{:<10x}".format("Address of raw data:",
            tls.addressof_raw_data[0], tls.addressof_raw_data[1]))
        print(format_hex.format("Size of raw data:",  len(tls.data_template)))
        print(format_hex.format("Characteristics:",   tls.characteristics))
        print(format_str.format("Section:",           tls.section.name))
        print(format_str.format("Data directory:",    str(tls.directory.type)))
        print("")


    def print_export(self):
        print("# Exports  ")
        exports = self.liefBinary.get_export()
        entries = exports.entries
        f_value = "{:<20} 0x{:<10x} 0x{:<10x} 0x{:<6x} 0x{:<6x} 0x{:<10x}"
        print(f_value.format(exports.name, exports.export_flags, exports.timestamp, exports.major_version, exports.minor_version, exports.ordinal_base))
        entries = sorted(entries, key=lambda e : e.ordinal)
        for entry in entries:
            extern = "[EXTERN]" if entry.is_extern else ""
            print("  {:<20} {:d} 0x{:<10x} {:<13}".format(entry.name[:20], entry.ordinal, entry.address, extern))
        print("")


    def print_debug(self):
        format_str = "{:<33} {:<30}"
        format_hex = "{:<33} 0x{:<28x}"
        format_dec = "{:<33} {:<30d}"

        debugs = self.liefBinary.debug
        print("\n# Debug  \n")
        print(f"## Debug ({len(debugs)})  ")
        for debug in debugs:
            print(format_hex.format("  Characteristics:",     debug.characteristics))
            print(format_hex.format("  Timestamp:",           debug.timestamp))
            print(format_dec.format("  Major version:",       debug.major_version))
            print(format_dec.format("  Minor version:",       debug.minor_version))
            print(format_str.format("  Type:",                str(debug.type).split(".")[-1]))
            print(format_hex.format("  Size of data:",        debug.sizeof_data))
            print(format_hex.format("  Address of raw data:", debug.addressof_rawdata))
            print(format_hex.format("  Pointer to raw data:", debug.pointerto_rawdata))

            if debug.has_code_view:
                code_view = debug.code_view
                cv_signature = code_view.cv_signature

                if cv_signature in (lief.PE.CODE_VIEW_SIGNATURES.PDB_70, lief.PE.CODE_VIEW_SIGNATURES.PDB_70):
                    sig_str = " ".join(map(lambda e : "{:02x}".format(e), code_view.signature))
                    print(format_str.format("  Code View Signature:", str(cv_signature).split(".")[-1]))
                    print(format_str.format("  Signature:", sig_str))
                    print(format_dec.format("  Age:", code_view.age))
                    print(format_str.format("  Filename:", code_view.filename))

            if debug.has_pogo:
                pogo = debug.pogo
                sig_str = str(pogo.signature).split(".")[-1]
                print(format_str.format("  Signature:", sig_str))
                print("Entries:")
                for entry in pogo.entries:
                    print("    {:<20} 0x{:x} ({:d})".format(entry.name, entry.start_rva, entry.size))

            print("\n")


    def print_signature(self):
        format_str = "{:<33} {:<30}"
        format_dec = "{:<33} {:<30d}"
        print("\n# Signature  \n")
        for signature in self.liefBinary.signatures:
            print(signature)

    
    def print_certificates(self):
        format_str = "{:<33} {:<30}"
        format_dec = "{:<33} {:<30d}"

        print("\n## Certificate(s)  \n")
        # Snippet taken from PEpper
        for item in self.liefBinary.signatures:
            for cert in item.certificates:
                valid_from = "-".join(map(str, cert.valid_from[:3]))
                dt = datetime.datetime.strptime(valid_from, '%Y-%m-%d')
                timestamp = time.mktime(dt.timetuple())
                cert_from = datetime.datetime.fromtimestamp(timestamp)
                valid_from_str = "-".join(map(str, cert.valid_from[:3])) + " " + ":".join(map(str, cert.valid_from[3:]))

                valid_to = "-".join(map(str, cert.valid_to[:3]))
                dt = datetime.datetime.strptime(valid_to, '%Y-%m-%d')
                timestamp = time.mktime(dt.timetuple())
                cert_to = datetime.datetime.fromtimestamp(timestamp)
                valid_to_str = "-".join(map(str, cert.valid_to[:3])) + " " + ":".join(map(str, cert.valid_to[3:]))

                sn_str = ":".join(["{:02x}".format(e) for e in cert.serial_number])

                if cert_from > datetime.datetime.now() or cert_to < datetime.datetime.now():
                    print("[!] **Invalid certificate, based on date!**  \n")
                else:
                    print("[*] Valid certificate  \n")
                # Print the cert no matter what
                print(format_str.format("  Version:",                      cert.version))
                print(format_str.format("  Serial Number:",                sn_str))
                print(format_str.format("  Signature Algorithm:",          lief.PE.oid_to_string(cert.signature_algorithm)))
                print(format_str.format("  Valid From:",                   valid_from_str))
                print(format_str.format("  Valid To:",                     valid_to_str))
                print(format_str.format("  Issuer:",                       cert.issuer))
                print(format_str.format("  Subject:",                      cert.subject))
                print("")

    def print_resources(self):
        print("\n# Resources  \n")
        manager = self.liefBinary.resources_manager

        print(manager)

        print("")

    def print_load_configuration(self):
        format_str = "{:<45} {:<30}"
        format_hex = "{:<45} 0x{:<28x}"
        format_dec = "{:<45} {:<30d}"

        print("\n# Load Configuration  \n")
        config = self.liefBinary.load_configuration


        print(format_str.format("  Version:",                          str(config.version).split(".")[-1]))
        print(format_dec.format("  Characteristics:",                  config.characteristics))
        print(format_dec.format("  Timedatestamp:",                    config.timedatestamp))
        print(format_dec.format("  Major version:",                    config.major_version))
        print(format_dec.format("  Minor version:",                    config.minor_version))
        print(format_hex.format("  Global flags clear:",               config.global_flags_clear))
        print(format_hex.format("  Global flags set:",                 config.global_flags_set))
        print(format_dec.format("  Critical section default timeout:", config.critical_section_default_timeout))
        print(format_hex.format("  Decommit free block threshold:",    config.decommit_free_block_threshold))
        print(format_hex.format("  Decommit total free threshold:",    config.decommit_total_free_threshold))
        print(format_hex.format("  Lock prefix table:",                config.lock_prefix_table))
        print(format_hex.format("  Maximum allocation size:",          config.maximum_allocation_size))
        print(format_hex.format("  Virtual memory threshold:",         config.virtual_memory_threshold))
        print(format_hex.format("  Process affinity mask:",            config.process_affinity_mask))
        print(format_hex.format("  Process heap flags:",               config.process_heap_flags))
        print(format_hex.format("  CSD Version:",                      config.csd_version))
        print(format_hex.format("  Reserved 1:",                       config.reserved1))
        print(format_hex.format("  Edit list:",                        config.editlist))
        print(format_hex.format("  Security cookie:",                  config.security_cookie))

        if isinstance(config, lief.PE.LoadConfigurationV0):
            print(format_hex.format("  SE handler table:", config.se_handler_table))
            print(format_dec.format("  SE handler count:", config.se_handler_count))

        if isinstance(config, lief.PE.LoadConfigurationV1):
            flags_str = " - ".join(map(lambda e : str(e).split(".")[-1], config.guard_cf_flags_list))
            print(format_hex.format("  GCF check function pointer:",    config.guard_cf_check_function_pointer))
            print(format_hex.format("  GCF dispatch function pointer:", config.guard_cf_dispatch_function_pointer))
            print(format_hex.format("  GCF function table :",           config.guard_cf_function_table))
            print(format_dec.format("  GCF Function count :",           config.guard_cf_function_count))
            print("{:<45} {} (0x{:x})".format("  Guard flags:", flags_str, int(config.guard_flags)))

        if isinstance(config, lief.PE.LoadConfigurationV2):
            code_integrity = config.code_integrity
            print("  Code Integrity:")
            print(format_dec.format("   " * 3 + "Flags:",          code_integrity.flags))
            print(format_dec.format("   " * 3 + "Catalog:",        code_integrity.catalog))
            print(format_hex.format("   " * 3 + "Catalog offset:", code_integrity.catalog_offset))
            print(format_dec.format("   " * 3 + "Reserved:",       code_integrity.reserved))

        if isinstance(config, lief.PE.LoadConfigurationV3):
            print(format_hex.format("  Guard address taken iat entry table:", config.guard_address_taken_iat_entry_table))
            print(format_hex.format("  Guard address taken iat entry count:", config.guard_address_taken_iat_entry_count))
            print(format_hex.format("  Guard long jump target table:",        config.guard_long_jump_target_table))
            print(format_hex.format("  Guard long jump target count:",        config.guard_long_jump_target_count))


        if isinstance(config, lief.PE.LoadConfigurationV4):
            print(format_hex.format("  Dynamic value relocation table:", config.dynamic_value_reloc_table))
            print(format_hex.format("  Hybrid metadata pointer:",        config.hybrid_metadata_pointer))


        if isinstance(config, lief.PE.LoadConfigurationV5):
            print(format_hex.format("  GRF failure routine:",                  config.guard_rf_failure_routine))
            print(format_hex.format("  GRF failure routine function pointer:", config.guard_rf_failure_routine_function_pointer))
            print(format_hex.format("  Dynamic value reloctable offset:",      config.dynamic_value_reloctable_offset))
            print(format_hex.format("  Dynamic value reloctable section:",     config.dynamic_value_reloctable_section))


        if isinstance(config, lief.PE.LoadConfigurationV6):
            print(format_hex.format("  GRF verify stackpointer function pointer:", config.guard_rf_verify_stackpointer_function_pointer))
            print(format_hex.format("  Hotpatch table offset:",                    config.hotpatch_table_offset))


        if isinstance(config, lief.PE.LoadConfigurationV7):
            print(format_hex.format("  Reserved 3:", config.reserved3))

        print("")


def get_yara_rules_path(path=None):
    """Check for yara-rules in ./rules, or use passed in path"""
    if not path:
        basePath = os.path.dirname(os.path.realpath(__file__))  # Path is now where the script is ran from
        path = os.path.join(basePath, 'rules')  # Append rules to path, this is where yara-rules should be
    print(f"yara-rules path is {path}")
    return path


def compileYaraRules(yaraRulesPath, yaraIndex="index.yar"):
    """Compile all files shown in passed in index (defaults to index.yar)"""
    indexLoc = os.path.join(yaraRulesPath, yaraIndex)
    print(f"Compiling yara-rules using default index.yar at: {indexLoc}")

    # Primarily ELF yara rules
    badImports = ['MALW_AZORULT.yar', 'MALW_Httpsd_ELF.yar', 'MALW_Mirai_Okiru_ELF.yar', 'MALW_Mirai_Satori_ELF.yar', 'MALW_Rebirth_Vulcan_ELF.yar', 
    'MALW_TinyShell_Backdoor_gen.yar', 'MALW_Torte_ELF.yar', 'TOOLKIT_Mandibule.yar']

    hugeDict = {}
    counter = 1

    with open(indexLoc, 'r') as f:
        for line in f:
            if not any(word in line for word in badImports):
                # Find the includes only
                if line.startswith('include "'):
                    # Remove the include " " piece.  Giving only the raw path.
                    includePath = line.partition('include "')[2][:-2]
                    if includePath.startswith('.'):
                        # This is a relative path.. fix it
                        fixedRule = yaraRulesPath + includePath.partition('.')[2]
                        hugeDict[str(counter)] = fixedRule
                        counter += 1
                    else:
                        hugeDict[str(counter)] = includePath
                        counter += 1
    #print(hugeDict)
    print(f"[*] Compiled {len(hugeDict)} yara rules.")
    #print("")

    rules = yara.compile(filepaths=hugeDict)
    return rules

def check_magic(args_file):
    try:
        # ELF or PE?
        with open(args_file, 'rb') as f:
            magic = f.read(4)
            #print(f"First 4 bytes: {magic}")
            if magic == b'\x7F\x45\x4c\x46':
                #print("Linux ELF found")
                return "elf"
            elif magic[0:2] == b'\x4d\x5a':
                #print("DOS MZ executable")
                return "pe"
            elif magic[0:2] == b'\x5a\x4d':
                #print("DOS ZM executable")
                return "pe"
            else:
                print("Not detecting ELF or PE")
                sys.exit(1)
    except Exception as e:
        print(e)
        sys.exit(1)

def main():
    args = parse_args()     # Verbose.. for now
    flavor = check_magic(args.binary_file)
    print("\n\n")                       # Remove me
    if flavor == "pe":
        binary = PE(args)
    elif flavor == "elf":
        binary = ELF(args)
    binary.print_information()          # Basic file info
    binary.print_sections()             # Sections glance, to see if anything interesting
    if not args.show_all:
        if flavor == "pe":
            binary.print_version_only()     # Print useful info from exe
        binary.print_import_name_only() # Print DLL import names only, when not using full
    # print headers (dos, pe, optional)
    if args.show_all:
        binary.print_header()
    # data directories
    if args.show_all:
        binary.print_data_directories()
    # symbols
    if args.show_all:
        binary.print_symbols()
    # imports
    if args.show_all and binary.liefBinary.has_imports:
        binary.print_imports()
    # tls
    if args.show_all and binary.liefBinary.has_tls:
        binary.print_tls()
    # exports
    if args.show_all and binary.liefBinary.has_exports:
        binary.print_export()
    # debug
    if args.show_all and binary.liefBinary.has_debug:
        binary.print_debug()
    # signature
    if args.show_all and binary.liefBinary.has_signatures:
        binary.print_signature()
    # certificate (from signature)
    if args.show_all and binary.liefBinary.has_signatures:
        binary.print_certificates()
    # resources
    if args.show_all and binary.liefBinary.has_resources:
        binary.print_resources()
    # load config
    if args.show_all and binary.liefBinary.has_configuration:
        binary.print_load_configuration()

    # To Do, validate path passed in..?
    if yaraInstalled and args.show_all:
        print("\n# Yara  \n")
        if not args.yara_rules_path:
            yaraRulesPath = get_yara_rules_path()
        elif args.yara_rules_path:
            yaraRulesPath = get_yara_rules_path(args.yara_rules_path)
        
        rules = compileYaraRules(yaraRulesPath)
    
        matches = rules.match(data=binary.rawBinary, fast=True)
        if matches:
            for hit in matches:
                if hit.meta.get('description'):
                    print(f"  Rule:  {hit.rule:<40} {hit.meta.get('description'):<20}")
                else:
                    print(f"  Rule:  {hit.rule:<40}")


if __name__ == "__main__":
    main()
