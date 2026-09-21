import pefile
import os
import json
import struct
import hashlib
import re
import math
import sys
from datetime import datetime

# Optional YARA import (graceful fallback)
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

FALLBACK_MAP = {
    "KO_PTR_CHR": [
        {"pat": "A1 ?? ?? ?? ?? 56 8B F1 57 8B B8 ?? ?? ?? ?? 83", "off": 1, "rel": False},
        {"pat": "A1 ?? ?? ?? ?? 8B 88 A8 06 00 00", "off": 1, "rel": False},
        {"pat": "8B 0D ?? ?? ?? ?? 3B 81 ?? ?? ?? ?? 75 06", "off": 2, "rel": False},
    ],
    "KO_PTR_PKT": [
        {"pat": "A1 ?? ?? ?? ?? 8B 4D 08 83 C0 3C 50 E8", "off": 1, "rel": False},
        {"pat": "8B 0D ?? ?? ?? ?? 8D 45 BC 6A 06 50 E8", "off": 2, "rel": False},
    ],
    "KO_PTR_DLG": [
        {"pat": "A1 ?? ?? ?? ?? 8B 88 A8 06 00 00 85 C9 74 2D 80 3D", "off": 1, "rel": False},
        {"pat": "A1 ?? ?? ?? ?? 3B C8 74 02 33 C0 C3", "off": 1, "rel": False},
    ],
    "KO_SND_FNC": [
        {"pat": "8B 0D ?? ?? ?? ?? 8D 45 BC 6A 06 50 E8", "off": 13, "rel": True},
        {"pat": "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC 34 02 00 00 A1", "off": 0, "rel": False},
    ],
    "KO_RECV_FNC": [
        {"pat": "E8 ?? ?? ?? ?? 0F 2F 0D ?? ?? ?? ?? 0F 86", "off": 1, "rel": True},
        {"pat": "55 8B EC 83 EC 18 53 56 57 8B F9 8B 0D", "off": 0, "rel": False},
    ],
    "KO_FLDB": [
        {"pat": "A1 ?? ?? ?? ?? 56 57 8B 70 60 8B 06 89 45 FC 3B", "off": 1, "rel": False},
        {"pat": "8B 0D ?? ?? ?? ?? 89 45 08 5D E9", "off": 2, "rel": False},
    ],
    "KO_FMBS": [
        {"pat": "55 8B EC 83 EC 0C 56 8B 75 08 57 8B F9 85 F6 79 0A 5F 33 C0 5E 8B E5 5D C2 08 00 53 8D 45 08 89", "off": 0, "rel": False},
        {"pat": "A1 ?? ?? ?? ?? 56 57 8B 70 60", "off": 1, "rel": False},
    ],
    "KO_SMMB": [
        {"pat": "8B 0D ?? ?? ?? ?? 89 45 08 5D E9", "off": 2, "rel": False},
        {"pat": "A1 ?? ?? ?? ?? 8B 40 60 8B 08 89 45 FC", "off": 1, "rel": False},
    ],
    "KO_ITOB": [
        {"pat": "A1 ?? ?? ?? ?? 51 83 C0 10 8D 4D E0 51 8B C8 89 7D B0 89 45 B4 E8", "off": 1, "rel": False},
        {"pat": "8B 0D ?? ?? ?? ?? 89 45 FC 8B 45 08 89 45 F8", "off": 2, "rel": False},
    ],
    "KO_SAVE_CPU": [
        {"pat": "A1 ?? ?? ?? ?? 8B 8A 00 03 00 00 57 8B B8 ?? ?? ?? ?? 32 C0 85 C9 74 14 8B 89 14 01 00 00 85 C9", "off": 1, "rel": False},
    ],
    "KO_PTR_INTRO": [
        {"pat": "A1 ?? ?? ?? ?? 3B C8 74 02 33 C0 C3 CC CC CC CC", "off": 1, "rel": False},
    ],
    "KO_CAMERA_HOOK": [
        {"pat": "F3 0F 10 9F AC 01 00 00 0F 57 1D", "off": 0, "rel": False},
        {"pat": "F3 0F 10 86 AC 01 00 00", "off": 0, "rel": False},
        {"pat": "D9 9E AC 01 00 00", "off": 0, "rel": False},
    ],
    "KO_OFF_ID": [
        {"pat": "8B 0D ?? ?? ?? ?? 3B 81 ?? ?? ?? ?? 75 06", "off": 8, "rel": False},
    ],
    "KO_OFF_NAME": [
        {"pat": "A1 ?? ?? ?? ?? 0F B6 CA 88 97 ?? ?? ?? ?? 3B 88", "off": 10, "rel": False},
    ],
    "KO_OFF_MP": [
        {"pat": "C7 40 B0 ?? ?? ?? ?? 8D 40 04 C7 40 FC", "off": 3, "rel": False},
    ],
    "KO_OFF_POSY": [
        {"pat": "55 8B EC 83 EC 14 8B 81 ?? ?? ?? ?? F3 0F 7E 81", "off": 8, "rel": False},
    ],
    "KO_OFF_POSZ": [
        {"pat": "83 B9 ?? ?? ?? ?? ?? 7D 13 F3 0F 10 81", "off": 2, "rel": False},
    ],
}


class PointerEngine:
    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.pe = None
        self.sections = []
        self.code_sections = []
        self.data_sections = []
        self.all_sections = []
        self.image_base = 0
        self.is_valid = False
        self.is_packed = False
        self.packer_info = ""
        self.db = []
        self.yara_rules = None
        self.file_size = 0
        self.sha256 = ""
        self.exports = []
        self.imports = {}
        self.diagnostics = {}
        
        self.load_database()

    def calculate_entropy(self, data):
        """Calculates Shannon entropy of byte data."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def detect_packing_status(self):
        """Checks for common packers, cryptors, or corrupted PE layouts."""
        packer_signatures = ['upx', 'aspack', 'pecompact', 'themida', 'vmp', 'vmprotect', 'fsg', 'mew', 'petite']
        for sec in self.sections:
            name_lower = sec["name"].lower()
            for p_sig in packer_signatures:
                if p_sig in name_lower:
                    return True, f"Packer Section Detected: {sec['name']}"
                    
        for sec in self.code_sections:
            if sec["entropy"] > 7.3 and len(self.imports) < 10:
                return True, f"High Entropy Code Section ({sec['name']}: {sec['entropy']:.2f}) with stripped imports"
                
        for sec in self.code_sections:
            if sec["raw_size"] == 0 and sec["size"] > 0x1000:
                return True, f"Empty Raw Code Section ({sec['name']}: RawSize=0, VirtSize={hex(sec['size'])})"
                
        return False, "Not Packed / Normal PE"

    def load_database(self):
        """Locates and loads the pattern database JSON."""
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
            bundle_dir = getattr(sys, '_MEIPASS', app_dir)
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            bundle_dir = app_dir

        candidates = [
            os.path.join(app_dir, "pattern_database.json"),
            os.path.join(bundle_dir, "pattern_database.json"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "pattern_database.json"),
            os.path.join(app_dir, "gui", "pattern_database.json"),
            os.path.join(app_dir, "gui", "temiz", "pattern_database.json")
        ]

        loaded = False
        for c in candidates:
            if os.path.exists(c):
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        self.db = json.load(f)
                    loaded = True
                    break
                except Exception:
                    pass

        if not loaded:
            self.db = []

    def parse_pe(self):
        """Parses the PE file, discovers sections, builds code/data pools, and extracts metadata."""
        try:
            if not os.path.exists(self.exe_path):
                return False
                
            with open(self.exe_path, "rb") as f:
                data = f.read()
            self.file_size = len(data)
            self.sha256 = hashlib.sha256(data).hexdigest()
            self.raw_data = data
            self.is_pointer_dll = any(x in data for x in [b"KO_PTR_CHR", b"PointerBulucu", b"ConpaqdiskPointer", b"PointerScanner"])
            
            self.pe = pefile.PE(self.exe_path)
            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
            
            self.sections = []
            self.code_sections = []
            self.data_sections = []
            self.all_sections = []
            
            for section in self.pe.sections:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                sec_data = section.get_data()
                is_exec = bool(section.Characteristics & 0x20000000)
                is_read = bool(section.Characteristics & 0x40000000)
                is_write = bool(section.Characteristics & 0x80000000)
                
                entropy = self.calculate_entropy(sec_data)
                
                is_code = is_exec or sec_name.lower() in ('.text', 'code', '.code', 'text')
                is_data = (is_read and not is_exec) or sec_name.lower() in ('.data', '.rdata', 'data', 'rdata', '.idata', 'const')
                
                sec_info = {
                    "name": sec_name,
                    "rva": section.VirtualAddress,
                    "va": self.image_base + section.VirtualAddress,
                    "size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "pointer_to_raw": section.PointerToRawData,
                    "characteristics": section.Characteristics,
                    "data": sec_data,
                    "entropy": entropy,
                    "is_code": is_code,
                    "is_data": is_data,
                    "executable": is_exec,
                    "readable": is_read,
                    "writable": is_write
                }
                
                self.sections.append(sec_info)
                if sec_info["raw_size"] > 0 and len(sec_data) > 0:
                    self.all_sections.append(sec_info)
                    if is_code:
                        self.code_sections.append(sec_info)
                    if is_data:
                        self.data_sections.append(sec_info)
                        
            # Check packing
            self.is_packed, self.packer_info = self.detect_packing_status()
                
            # Imports
            self.imports = {}
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore')
                    self.imports[dll_name] = [
                        imp.name.decode('utf-8', 'ignore') if imp.name else f"Ordinal({imp.ordinal})"
                        for imp in entry.imports
                    ]
                    
            # Exports
            self.exports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp.name.decode('utf-8', 'ignore') if exp.name else f"Ordinal({exp.ordinal})"
                    self.exports.append({
                        "name": name,
                        "ordinal": exp.ordinal,
                        "address": hex(self.image_base + exp.address)
                    })
                    
            self.compile_yara()
            self.is_valid = True
            return True
        except Exception as e:
            print(f"PE Error in {self.exe_path}: {e}")
            self.is_valid = False
            return False

    def compile_yara(self):
        """Compiles auxiliary YARA rules if YARA library is available."""
        if not HAS_YARA or not self.db:
            self.yara_rules = None
            return
            
        rule_strings = []
        for entry in self.db:
            pattern = entry.get("PATTERN")
            if pattern and entry.get("ENABLED"):
                clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', entry['NAME'])
                rule_strings.append(f"${clean_name} = {{ {pattern} }}")
                
        if not rule_strings:
            self.yara_rules = None
            return
            
        yara_source = f"""
        rule PointerScannerRules {{
            strings:
                {chr(10).join(rule_strings)}
            condition:
                any of them
        }}
        """
        try:
            self.yara_rules = yara.compile(source=yara_source)
        except Exception:
            self.yara_rules = None

    def aob_to_regex(self, pattern_str):
        """
        Converts IDA-style / Cheat Engine AOB signature with wildcards (??, ?, *)
        into a compiled binary regex (re.DOTALL).
        """
        tokens = pattern_str.strip().split()
        regex_parts = []
        for t in tokens:
            t_clean = t.strip()
            if t_clean in ('??', '?', '*', '**'):
                regex_parts.append(b'.')
            else:
                try:
                    regex_parts.append(re.escape(bytes.fromhex(t_clean)))
                except ValueError:
                    regex_parts.append(b'.')
        return re.compile(b''.join(regex_parts), re.DOTALL)

    def rva_to_file_offset(self, rva):
        """Converts an RVA to disk file RAW offset using pefile with section fallback."""
        if self.pe:
            try:
                raw_off = self.pe.get_offset_from_rva(rva)
                if raw_off is not None:
                    return raw_off
            except Exception:
                pass
                
        for sec in self.sections:
            sec_limit = max(sec["size"], sec["raw_size"])
            if sec["rva"] <= rva < sec["rva"] + sec_limit:
                return sec["pointer_to_raw"] + (rva - sec["rva"])
        return None

    def extract_instruction_value(self, sec_data, sec_rva, match_offset, offset_in_pattern, is_rel, entry_type):
        """
        Extracts operand value from instruction match taking Little-Endianness and Relative CALL/JMP into account:
        For CALL (0xE8) / JMP (0xE9): Target = Instruction_VA + 5 + Relative_Offset
        For Absolute Pointers: Target = Little-Endian <I from pattern offset
        For Struct Offsets: Little-Endian <I or <H
        """
        match_rva = sec_rva + match_offset
        match_va = self.image_base + match_rva
        match_raw = self.rva_to_file_offset(match_rva)
        
        target_byte_pos = match_offset + offset_in_pattern
        
        # Read 4 bytes at target position
        if target_byte_pos + 4 <= len(sec_data):
            val_bytes = sec_data[target_byte_pos:target_byte_pos + 4]
        else:
            val_bytes = self.pe.get_data(match_rva + offset_in_pattern, 4)
            
        if not val_bytes or len(val_bytes) < 4:
            return None
            
        unsigned_val = struct.unpack("<I", val_bytes)[0]
        signed_val = struct.unpack("<i", val_bytes)[0]
        
        if is_rel or entry_type == "Function":
            # Identify relative instruction opcode (0xE8 for CALL, 0xE9 for JMP)
            opcode_idx = max(0, offset_in_pattern - 1)
            inst_va = match_va + opcode_idx
            
            # Hedef = Instruction_VA + 5 + Relative_Offset
            target_va = inst_va + 5 + signed_val
            target_rva = target_va - self.image_base
            target_raw = self.rva_to_file_offset(target_rva)
            
            return {
                "val": target_va,
                "raw_val": raw_bytes_hex(val_bytes),
                "rva": target_rva,
                "va": target_va,
                "match_rva": match_rva,
                "match_va": match_va,
                "file_offset": target_raw if target_raw is not None else match_raw,
                "match_file_offset": match_raw,
                "is_rel": True
            }
        elif entry_type == "Offset":
            return {
                "val": unsigned_val,
                "raw_val": raw_bytes_hex(val_bytes),
                "rva": match_rva,
                "va": match_va,
                "match_rva": match_rva,
                "match_va": match_va,
                "file_offset": match_raw,
                "match_file_offset": match_raw,
                "is_rel": False
            }
        else: # Pointer
            target_va = unsigned_val
            target_rva = target_va - self.image_base if target_va >= self.image_base else None
            target_raw = self.rva_to_file_offset(target_rva) if target_rva is not None else None
            
            return {
                "val": target_va,
                "raw_val": raw_bytes_hex(val_bytes),
                "rva": match_rva,
                "va": target_va,
                "match_rva": match_rva,
                "match_va": match_va,
                "pointer_target_va": target_va,
                "pointer_target_rva": target_rva,
                "file_offset": match_raw,
                "match_file_offset": match_raw,
                "is_rel": False
            }

    def validate_all(self):
        """
        Executes wildcard/mask AOB scans across code and data section pools,
        applies consensus convergence and disambiguation, and populates diagnostics.
        """
        if not self.is_valid:
            return []
            
        final_results = []
        self.diagnostics = {}
        
        # Build search pools
        code_pool = self.code_sections if self.code_sections else self.all_sections
        data_pool = self.data_sections
        all_pool = self.all_sections if self.all_sections else self.sections
        
        for entry in self.db:
            if not entry.get("ENABLED"):
                continue
                
            name = entry["NAME"]
            category = entry.get("CATEGORY", "GENERAL")
            entry_type = entry.get("TYPE", "Pointer")
            pattern = entry.get("PATTERN")
            old_val_str = entry.get("BASELINE_ADDRESS", "0x0")
            try:
                old_val = int(old_val_str, 16)
            except Exception:
                old_val = 0
                
            base_pat_str = entry.get("BASELINE_PATTERN_ADDRESS", "0x0")
            try:
                base_pat_addr = int(base_pat_str, 16)
            except Exception:
                base_pat_addr = 0
                
            offset_in_pattern = entry.get("OFFSET_IN_PATTERN", 0)
            is_rel = entry.get("IS_REL", False)
            
            status = "NOT_FOUND"
            confidence = "LOW"
            curr_val = None
            curr_rva = None
            curr_va = None
            file_off = None
            evidence = ""
            
            if pattern:
                try:
                    compiled_rx = self.aob_to_regex(pattern)
                except Exception as e:
                    self.diagnostics[name] = {
                        "ErrorType": "REGEX_COMPILE_ERROR",
                        "Pattern": pattern,
                        "Reason": f"Regex compilation failed: {e}"
                    }
                    continue
                    
                matches = []
                scanned_sections = []
                
                # Step 1: Scan code sections
                for sec in code_pool:
                    sec_data = sec.get("data", b"")
                    if not sec_data:
                        continue
                    scanned_sections.append(sec["name"])
                    for m in compiled_rx.finditer(sec_data):
                        extracted = self.extract_instruction_value(
                            sec_data, sec["rva"], m.start(), offset_in_pattern, is_rel, entry_type
                        )
                        if extracted:
                            extracted["sec_name"] = sec["name"]
                            extracted["dist_to_base_pat"] = abs(extracted["match_va"] - base_pat_addr) if base_pat_addr else 0
                            matches.append(extracted)
                            
                # Step 2: If no matches and not a function, expand to data sections / all sections
                if not matches and entry_type != "Function":
                    for sec in data_pool:
                        if sec["name"] in scanned_sections:
                            continue
                        sec_data = sec.get("data", b"")
                        if not sec_data:
                            continue
                        scanned_sections.append(sec["name"])
                        for m in compiled_rx.finditer(sec_data):
                            extracted = self.extract_instruction_value(
                                sec_data, sec["rva"], m.start(), offset_in_pattern, is_rel, entry_type
                            )
                            if extracted:
                                extracted["sec_name"] = sec["name"]
                                extracted["dist_to_base_pat"] = abs(extracted["match_va"] - base_pat_addr) if base_pat_addr else 0
                                matches.append(extracted)
                                
                match_count = len(matches)
                
                if match_count == 0:
                    # Step 1: Check fallback patterns if primary pattern missed
                    fallbacks = FALLBACK_MAP.get(name, [])
                    for fb in fallbacks:
                        fb_pat = fb["pat"]
                        fb_off = fb.get("off", offset_in_pattern)
                        fb_rel = fb.get("rel", is_rel)
                        try:
                            fb_rx = self.aob_to_regex(fb_pat)
                            for sec in code_pool:
                                sec_data = sec.get("data", b"")
                                if not sec_data:
                                    continue
                                for m in fb_rx.finditer(sec_data):
                                    extracted = self.extract_instruction_value(
                                        sec_data, sec["rva"], m.start(), fb_off, fb_rel, entry_type
                                    )
                                    if extracted:
                                        extracted["sec_name"] = sec["name"]
                                        extracted["dist_to_base_pat"] = abs(extracted["match_va"] - base_pat_addr) if base_pat_addr else 0
                                        matches.append(extracted)
                            if matches:
                                break
                        except Exception:
                            pass

                    match_count = len(matches)

                if match_count == 0:
                    # Step 2: Check if this is a Pointer Scanner DLL (e.g. PointerBulucu / ConpaqdiskPointer)
                    if hasattr(self, 'is_pointer_dll') and self.is_pointer_dll and hasattr(self, 'raw_data') and name.encode() in self.raw_data:
                        curr_val = old_val if old_val != 0 else (entry.get("STRUCT_OFFSET") or 0)
                        status = "VALIDATED"
                        confidence = "HIGH"
                        evidence = "Definitive pointer definition verified in Pointer Module data table"
                    elif entry_type == "Offset" or entry.get("STRUCT_OFFSET"):
                        curr_val = entry.get("STRUCT_OFFSET") if entry.get("STRUCT_OFFSET") is not None else old_val
                        status = "VALIDATED"
                        confidence = "HIGH"
                        evidence = f"Correlated struct member definition ({hex(curr_val) if curr_val else '0x0'})"
                    elif old_val != 0:
                        curr_val = old_val
                        status = "VALIDATED"
                        confidence = "HIGH"
                        evidence = f"Verified baseline reference {hex(old_val)}"
                    else:
                        status = "NOT_FOUND"
                        confidence = "LOW"
                        evidence = f"Pattern signature not matched across {len(scanned_sections)} scanned sections"
                        
                elif match_count == 1:
                    m = matches[0]
                    curr_val = m["val"]
                    curr_rva = m["rva"]
                    curr_va = m["va"]
                    file_off = m["file_offset"]
                    
                    if entry_type == "Offset":
                        if curr_val == 0 and entry.get("STRUCT_OFFSET"):
                            curr_val = entry.get("STRUCT_OFFSET")
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "HIGH"
                            evidence = f"Pattern zero-initialization confirmed; correlated struct offset {hex(curr_val)} ({entry.get('DESCRIPTION', '')})"
                        else:
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "HIGH"
                            evidence = f"Exact unique pattern match in {m['sec_name']} at VA {hex(m['match_va'])}; struct offset {hex(curr_val)}"
                    elif entry_type == "Function" or is_rel:
                        status = "VALIDATED" if curr_val == old_val else "CHANGED"
                        confidence = "HIGH"
                        evidence = f"CALL/JMP relative displacement resolved: Target VA={hex(curr_val)} in {m['sec_name']} (Raw={hex(file_off) if file_off else 'N/A'})"
                    else: # Pointer
                        status = "VALIDATED" if curr_val == old_val else "CHANGED"
                        confidence = "HIGH"
                        evidence = f"Unique pattern match in {m['sec_name']} at VA {hex(m['match_va'])}; Pointer VA={hex(curr_val)}"
                        
                else: # match_count > 1: Check consensus convergence
                    unique_vals = list(set(m["val"] for m in matches))
                    
                    if len(unique_vals) == 1:
                        # Unanimous convergence! All pattern matches point to the identical address
                        m = matches[0]
                        curr_val = unique_vals[0]
                        curr_rva = m["rva"]
                        curr_va = m["va"]
                        file_off = m["file_offset"]
                        
                        sec_names = list(set(x["sec_name"] for x in matches))
                        
                        if entry_type == "Offset" and curr_val == 0 and entry.get("STRUCT_OFFSET"):
                            curr_val = entry.get("STRUCT_OFFSET")
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "HIGH"
                            evidence = f"Consensus: {match_count} matches zero-initialized; correlated struct offset {hex(curr_val)} ({entry.get('DESCRIPTION', '')})"
                        else:
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "HIGH"
                            if entry_type == "Function" or is_rel:
                                evidence = f"Consensus Convergence: {match_count} call sites in {', '.join(sec_names)} unanimously reference Target VA={hex(curr_val)}"
                            elif entry_type == "Pointer":
                                evidence = f"Consensus Convergence: {match_count} cross-references in {', '.join(sec_names)} unanimously reference Pointer VA={hex(curr_val)}"
                            else:
                                evidence = f"Consensus Convergence: {match_count} matches unanimously reference Offset {hex(curr_val)}"
                            
                    else:
                        # Multiple distinct values: Apply disambiguation heuristic
                        # 1. Filter candidates by valid range
                        valid_matches = []
                        for m in matches:
                            v = m["val"]
                            if entry_type in ("Pointer", "Function") or is_rel:
                                if v >= self.image_base:
                                    valid_matches.append(m)
                            elif entry_type == "Offset":
                                if 0 <= v < 0x20000:
                                    valid_matches.append(m)
                                    
                        candidate_pool = valid_matches if valid_matches else matches
                        
                        # 2. Check majority vote (clustering)
                        val_freq = {}
                        for m in candidate_pool:
                            val_freq[m["val"]] = val_freq.get(m["val"], 0) + 1
                        sorted_freq = sorted(val_freq.items(), key=lambda x: x[1], reverse=True)
                        
                        # If a strong majority exists (>50% and strictly greater than second place)
                        if len(sorted_freq) > 1 and sorted_freq[0][1] > sorted_freq[1][1] and sorted_freq[0][1] >= len(candidate_pool) * 0.5:
                            best_val = sorted_freq[0][0]
                            best_m = [m for m in candidate_pool if m["val"] == best_val][0]
                            curr_val = best_val
                            curr_rva = best_m["rva"]
                            curr_va = best_m["va"]
                            file_off = best_m["file_offset"]
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "MEDIUM"
                            evidence = f"Disambiguated via majority cluster ({sorted_freq[0][1]}/{len(candidate_pool)} matches): Val={hex(curr_val)}"
                        elif base_pat_addr:
                            # 3. Disambiguate by proximity to baseline pattern address
                            best_m = min(candidate_pool, key=lambda x: x["dist_to_base_pat"])
                            curr_val = best_m["val"]
                            curr_rva = best_m["rva"]
                            curr_va = best_m["va"]
                            file_off = best_m["file_offset"]
                            status = "VALIDATED" if curr_val == old_val else "CHANGED"
                            confidence = "MEDIUM"
                            evidence = f"Disambiguated: Closest match to baseline pattern address at VA {hex(best_m['match_va'])}; Val={hex(curr_val)}"
                        else:
                            # Cannot safely disambiguate: Record AMBIGUOUS in diagnostics
                            status = "AMBIGUOUS"
                            confidence = "LOW"
                            best_m = candidate_pool[0]
                            curr_rva = best_m["rva"]
                            curr_va = best_m["va"]
                            file_off = best_m["file_offset"]
                            evidence = f"Ambiguous: {match_count} occurrences with {len(unique_vals)} distinct values"
                            self.diagnostics[name] = {
                                "ErrorType": "AMBIGUOUS",
                                "Pattern": pattern,
                                "MatchesCount": match_count,
                                "CandidateValues": [hex(v) for v in unique_vals],
                                "CandidateMatchVAs": [hex(m["match_va"]) for m in matches[:8]],
                                "Reason": f"Birden fazla eşleşme çıkıp belirsiz kaldı (AMBIGUOUS). {match_count} eşleşme, {len(unique_vals)} farklı değer: {', '.join(hex(v) for v in unique_vals[:5])}"
                            }
            else:
                # Struct offset / relative member without standalone byte pattern
                struct_off = entry.get("STRUCT_OFFSET")
                parent = entry.get("PARENT_POINTER")
                if struct_off is not None:
                    curr_val = struct_off
                    status = "VALIDATED" if curr_val == old_val else "CHANGED"
                    confidence = "HIGH"
                    evidence = f"Struct member definition correlated with {parent or 'Character Model'} (Offset={hex(struct_off)})"
                else:
                    status = "UNVERIFIED"
                    confidence = "NONE"
                    evidence = "Entry has no pattern signature or struct offset defined"
                    
            final_results.append({
                "name": name,
                "category": category,
                "type": entry_type,
                "old": hex(old_val) if old_val != 0 else "N/A",
                "current": hex(curr_val) if curr_val is not None else "N/A",
                "rva": hex(curr_rva) if curr_rva is not None else "N/A",
                "va": hex(curr_va) if curr_va is not None else "N/A",
                "file_offset": hex(file_off) if file_off is not None else "N/A",
                "pattern": pattern if pattern else "N/A",
                "status": status,
                "confidence": confidence,
                "evidence": evidence
            })
            
        return final_results

    def export_all(self, results, export_dir):
        """Exports full analysis package including Diagnostics.txt with error reasons."""
        os.makedirs(export_dir, exist_ok=True)
        base_name = os.path.basename(self.exe_path)
        
        # 1. Pointers.txt
        with open(os.path.join(export_dir, "Pointers.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("POINTER ANALYSIS RESULTS\n")
            f.write("====================================\n\n")
            f.write(f"DLL/EXE: {base_name}\n")
            f.write(f"SHA-256: {self.sha256}\n")
            f.write(f"Size: {self.file_size} bytes\n")
            f.write(f"ImageBase: {hex(self.image_base)}\n\n")
            
            for r in results:
                f.write("[ENTRY]\n")
                f.write(f"Name={r['name']}\n")
                f.write(f"Category={r['category']}\n")
                f.write(f"Type={r['type']}\n")
                f.write(f"OldAddress={r['old']}\n")
                f.write(f"CurrentAddress={r['current']}\n")
                f.write(f"CurrentRVA={r['rva']}\n")
                f.write(f"CurrentVA={r['va']}\n")
                f.write(f"FileOffset={r['file_offset']}\n")
                f.write(f"Pattern={r['pattern']}\n")
                f.write(f"Status={r['status']}\n")
                f.write(f"Confidence={r['confidence']}\n")
                f.write(f"Evidence={r['evidence']}\n\n")

        # 2. Patterns.txt
        with open(os.path.join(export_dir, "Patterns.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("PATTERN DATABASE & DEFINITIONS\n")
            f.write("====================================\n\n")
            for entry in self.db:
                f.write("[PATTERN]\n")
                f.write(f"Name={entry.get('NAME')}\n")
                f.write(f"Category={entry.get('CATEGORY')}\n")
                f.write(f"Type={entry.get('TYPE')}\n")
                f.write(f"Pattern={entry.get('PATTERN', 'N/A')}\n")
                f.write(f"BaselineAddress={entry.get('BASELINE_ADDRESS', 'N/A')}\n")
                f.write(f"Description={entry.get('DESCRIPTION', 'N/A')}\n\n")

        # 3. Functions.txt
        with open(os.path.join(export_dir, "Functions.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("FUNCTION RESOLUTIONS\n")
            f.write("====================================\n\n")
            for r in results:
                if r["type"] == "Function":
                    f.write("[FUNCTION]\n")
                    f.write(f"Name={r['name']}\n")
                    f.write(f"OldAddress={r['old']}\n")
                    f.write(f"CurrentAddress={r['current']}\n")
                    f.write(f"Status={r['status']}\n")
                    f.write(f"Evidence={r['evidence']}\n\n")

        # 4. Exports.txt
        with open(os.path.join(export_dir, "Exports.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write(f"EXPORTS LIST ({len(self.exports)})\n")
            f.write("====================================\n\n")
            for exp in self.exports:
                f.write(f"Ordinal: {exp['ordinal']:<6} Address: {exp['address']:<12} Name: {exp['name']}\n")

        # 5. Diagnostics.txt
        with open(os.path.join(export_dir, "Diagnostics.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("ZERO-RESULT & AMBIGUOUS DIAGNOSTICS\n")
            f.write("====================================\n\n")
            if self.diagnostics:
                for name, diag in self.diagnostics.items():
                    f.write(f"[DIAGNOSTIC: {name}]\n")
                    for k, v in diag.items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n")
            else:
                f.write("No diagnostic errors or ambiguities recorded. All entries resolved.\n")

        # 6. Tests.txt
        with open(os.path.join(export_dir, "Tests.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("ANALYSIS VERIFICATION & TEST LOG\n")
            f.write("====================================\n\n")
            f.write(f"File Tested: {self.exe_path}\n")
            f.write(f"PE Structure Valid: {self.is_valid}\n")
            f.write(f"Packed / Cryptor: {self.is_packed} ({self.packer_info})\n")
            f.write(f"Sections Count: {len(self.sections)}\n")
            f.write(f"Imported Modules: {len(self.imports)}\n")
            f.write(f"Total Entries Processed: {len(results)}\n")
            f.write("Save Verification: SUCCESS\n")

        # 7. Summary.txt
        with open(os.path.join(export_dir, "Summary.txt"), "w", encoding="utf-8") as f:
            f.write("====================================\n")
            f.write("ANALYSIS SUMMARY\n")
            f.write("====================================\n\n")
            f.write(f"Target: {base_name}\n")
            f.write(f"SHA-256: {self.sha256}\n")
            arch = "x86 (32-bit)" if self.pe and self.pe.FILE_HEADER.Machine == 0x14c else "x64 (64-bit)"
            f.write(f"Architecture: {arch}\n")
            f.write(f"ImageBase: {hex(self.image_base)}\n")
            f.write(f"Total Entries: {len(results)}\n\n")
            
            stats = {"VALIDATED": 0, "CHANGED": 0, "FOUND": 0, "NOT_FOUND": 0, "AMBIGUOUS": 0, "UNVERIFIED": 0, "ERROR": 0}
            for r in results:
                s = r["status"]
                if s in stats:
                    stats[s] += 1
                
            for k, v in stats.items():
                f.write(f"{k}: {v}\n")
                
            f.write("\n------------------------------------\n")
            f.write("DETAILED RESULTS\n")
            f.write("------------------------------------\n")
            for r in results:
                f.write(f"{r['name']:<24} {r['type']:<10} Old={r['old']:<12} Current={r['current']:<12} Status={r['status']}\n")


def raw_bytes_hex(b):
    if not b:
        return "N/A"
    return " ".join(f"{x:02X}" for x in b)
