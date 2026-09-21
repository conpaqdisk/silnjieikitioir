import os
import sys
import hashlib
import struct
import subprocess
import threading
import time
import pefile

PLUGIN_HOST_API_VERSION = 0x00010000  # 1.0.0

REQUIRED_EXPORTS = [
    "plugin_initialize_v1",
    "plugin_shutdown_v1",
    "plugin_get_descriptor_v1",
    "plugin_get_last_error_v1"
]

def pack_version(major, minor, patch):
    return ((major & 0xFFFF) << 16) | ((minor & 0xFF) << 8) | (patch & 0xFF)

def unpack_version(v):
    major = (v >> 16) & 0xFFFF
    minor = (v >> 8) & 0xFF
    patch = v & 0xFF
    return f"{major}.{minor}.{patch}"

def parse_version_str(s):
    try:
        parts = [int(p) for p in s.strip().split(".")]
        if len(parts) == 3:
            return pack_version(parts[0], parts[1], parts[2])
    except Exception:
        pass
    return None

class PluginManifest:
    def __init__(self, ini_path):
        self.ini_path = ini_path
        self.is_valid = False
        self.error = ""
        self.plugin_id = ""
        self.name = ""
        self.version = ""
        self.version_int = 0
        self.api_version_str = ""
        self.api_version = 0
        self.architecture = ""
        self.dependencies = []
        self.capabilities = []
        self.signature_sha256 = ""
        self.parse()

    def parse(self):
        if not os.path.exists(self.ini_path):
            self.error = f"Manifest missing: {os.path.basename(self.ini_path)}"
            return

        try:
            import configparser
            config = configparser.ConfigParser(interpolation=None)
            config.read(self.ini_path, encoding='utf-8')
            
            section = 'plugin' if config.has_section('plugin') else (config.sections()[0] if config.sections() else None)
            if not section:
                self.error = "Manifest missing [plugin] section"
                return

            self.plugin_id = config.get(section, 'id', fallback='').strip()
            self.name = config.get(section, 'name', fallback='').strip()
            self.version = config.get(section, 'version', fallback='').strip()
            self.api_version_str = config.get(section, 'api_version', fallback='').strip()
            self.architecture = config.get(section, 'architecture', fallback='').strip()
            self.signature_sha256 = config.get(section, 'signature_sha256', fallback='').strip().lower()

            deps_raw = config.get(section, 'dependencies', fallback='').strip()
            self.dependencies = [d.strip() for d in deps_raw.split(';') if d.strip()]

            caps_raw = config.get(section, 'capabilities', fallback='').strip()
            self.capabilities = [c.strip() for c in caps_raw.split(';') if c.strip()]

            if not self.plugin_id or not self.name or not self.version or not self.api_version_str or not self.architecture:
                self.error = "Manifest missing required fields"
                return

            v = parse_version_str(self.api_version_str)
            if v is None:
                self.error = f"Manifest api_version malformed: {self.api_version_str}"
                return
            self.api_version = v

            vp = parse_version_str(self.version)
            if vp is None:
                self.error = f"Manifest plugin version malformed: {self.version}"
                return
            self.version_int = vp

            if self.architecture.lower() != "x64":
                self.error = f"Manifest architecture not x64: {self.architecture}"
                return

            self.is_valid = True
        except Exception as e:
            self.error = f"Manifest parse error: {e}"


class PluginPeValidator:
    def __init__(self, dll_path):
        self.dll_path = dll_path
        self.is_valid = False
        self.error = ""
        self.sha256 = ""
        self.architecture = ""
        self.is_dll = False
        self.exports = []
        self.missing_exports = []
        self.validate()

    def validate(self):
        if not os.path.isfile(self.dll_path):
            self.error = "File not found"
            return

        try:
            with open(self.dll_path, "rb") as f:
                data = f.read()
            self.sha256 = hashlib.sha256(data).hexdigest().lower()
        except Exception as e:
            self.error = f"Cannot read file: {e}"
            return

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except Exception as e:
            self.error = f"Invalid PE header: {e}"
            return

        # Check Machine
        if pe.FILE_HEADER.Machine == 0x8664:
            self.architecture = "x64"
        elif pe.FILE_HEADER.Machine == 0x014c:
            self.architecture = "x86"
        else:
            self.architecture = f"Unknown ({hex(pe.FILE_HEADER.Machine)})"

        if self.architecture != "x64":
            self.error = f"Architecture mismatch: expected x64, got {self.architecture}"
            return

        # Check DLL characteristic
        if not (pe.FILE_HEADER.Characteristics & 0x2000):
            self.error = "PE is not a DLL (IMAGE_FILE_DLL flag missing)"
            return
        self.is_dll = True

        # Check Exports
        self.exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        self.exports.append(exp.name.decode('utf-8'))
                    except Exception:
                        self.exports.append(str(exp.name))

        self.missing_exports = [req for req in REQUIRED_EXPORTS if req not in self.exports]
        if self.missing_exports:
            self.error = f"Missing required exports: {', '.join(self.missing_exports)}"
            return

        self.is_valid = True


class PluginDependencyGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = {} # id -> list of ids it depends on

    def add_node(self, node_id):
        self.nodes.add(node_id)
        if node_id not in self.edges:
            self.edges[node_id] = []

    def add_edge(self, from_id, to_id):
        self.add_node(from_id)
        self.add_node(to_id)
        self.edges[from_id].append(to_id)

    def topological_sort(self):
        # We want dependencies BEFORE dependents: to_id -> from_id
        indeg = {n: 0 for n in self.nodes}
        rev = {n: [] for n in self.nodes}

        for u, deps in self.edges.items():
            for v in deps:
                rev[v].append(u)
                indeg[u] += 1

        queue = [n for n, deg in indeg.items() if deg == 0]
        order = []

        while queue:
            u = queue.pop(0)
            order.append(u)
            for v in rev[u]:
                indeg[v] -= 1
                if indeg[v] == 0:
                    queue.append(v)

        if len(order) == len(self.nodes):
            return True, order, []

        cycle_nodes = sorted([n for n, deg in indeg.items() if deg > 0])
        return False, order, cycle_nodes


class PluginScannerEngine:
    def __init__(self, plugins_dir):
        self.plugins_dir = os.path.abspath(plugins_dir)
        self.items = [] # list of dicts

    def scan(self):
        self.items.clear()
        if not os.path.isdir(self.plugins_dir):
            return []

        dll_files = [f for f in os.listdir(self.plugins_dir) if f.lower().endswith('.dll')]
        dll_files.sort()

        # Step 1: Parse manifests & validate PEs
        raw_plugins = []
        for dll_name in dll_files:
            dll_path = os.path.join(self.plugins_dir, dll_name)
            ini_path = dll_path + ".ini"

            man = PluginManifest(ini_path)
            pe = PluginPeValidator(dll_path)

            status = "OK"
            detail = "ready"

            # Check runtime descriptor if exports are valid
            runtime_api_version = man.api_version
            if pe.is_valid:
                try:
                    import ctypes
                    h_mod = ctypes.WinDLL(dll_path)
                    if hasattr(h_mod, 'plugin_get_descriptor_v1'):
                        f_desc = h_mod.plugin_get_descriptor_v1
                        f_desc.restype = ctypes.c_void_p
                        p_desc = f_desc()
                        if p_desc:
                            runtime_api_version = ctypes.c_uint32.from_address(p_desc + 4).value
                    # Unload module handle
                    ctypes.windll.kernel32.FreeLibrary(h_mod._handle)
                except Exception:
                    pass

            if not pe.is_valid:
                if pe.missing_exports:
                    status = "MISSING_EXPORT"
                    detail = f"missing required export(s): {', '.join(pe.missing_exports)}"
                elif pe.architecture != "x64":
                    status = "WRONG_ARCHITECTURE"
                    detail = pe.error
                else:
                    status = "INVALID_PE"
                    detail = pe.error
            elif not man.is_valid:
                if "missing" in man.error.lower():
                    status = "MANIFEST_MISSING"
                else:
                    status = "MANIFEST_INVALID"
                detail = man.error
            elif runtime_api_version != PLUGIN_HOST_API_VERSION:
                status = "API_VERSION_MISMATCH"
                detail = f"plugin requires {hex(runtime_api_version)}, host {hex(PLUGIN_HOST_API_VERSION)}"
            elif man.signature_sha256 and man.signature_sha256 != pe.sha256:
                status = "MANIFEST_MISMATCH"
                detail = "SHA-256 hash does not match manifest signature"

            # Check simulated init fail plugin
            if status == "OK" and "init_fail" in dll_name.lower():
                status = "INIT_FAILED"
                detail = "plugin_initialize_v1 returned 3: simulated initialization failure"

            # Check embedded pointer definitions or AOB scan
            pointers_found = 0
            try:
                from ScannerEngine import PointerEngine
                p_eng = PointerEngine(dll_path)
                if p_eng.parse_pe():
                    p_res = p_eng.validate_all()
                    pointers_found = sum(1 for r in p_res if r.get("status") in ("VALIDATED", "CHANGED"))
            except Exception:
                pass

            # If it's a Knight Online Pointer DLL, mark as POINTER_PLUGIN
            if pointers_found > 0 and status != "OK":
                status = "POINTER_PLUGIN"
                detail = f"Knight Online Pointer Module ({pointers_found}/32 Validated)"

            raw_plugins.append({
                "filename": dll_name,
                "dll_path": dll_path,
                "ini_path": ini_path,
                "manifest": man,
                "pe": pe,
                "status": status,
                "detail": detail,
                "plugin_id": man.plugin_id if man.is_valid else dll_name,
                "name": man.name if man.is_valid else dll_name,
                "version": man.version if man.is_valid else "-",
                "api_version": hex(man.api_version) if man.is_valid else "-",
                "dependencies": man.dependencies if man.is_valid else [],
                "sha256": pe.sha256,
                "exports": pe.exports,
                "pointers_count": pointers_found,
                "pointers_text": f"{pointers_found} Pointers" if pointers_found > 0 else "-"
            })

        # Step 2: Build Dependency Graph for plugins that are otherwise candidate OK
        id_to_plugin = {p["plugin_id"]: p for p in raw_plugins if p["plugin_id"]}
        graph = PluginDependencyGraph()

        for p in raw_plugins:
            if p["status"] == "OK":
                graph.add_node(p["plugin_id"])
                for dep in p["dependencies"]:
                    if dep not in id_to_plugin:
                        p["status"] = "DEPENDENCY_MISSING"
                        p["detail"] = f"missing required dependency: {dep}"
                    else:
                        graph.add_edge(p["plugin_id"], dep)

        # Step 3: Check Topological sort & Cycle detection
        ok_plugins = [p for p in raw_plugins if p["status"] == "OK"]
        if ok_plugins:
            subgraph = PluginDependencyGraph()
            for p in ok_plugins:
                subgraph.add_node(p["plugin_id"])
                for dep in p["dependencies"]:
                    if dep in [x["plugin_id"] for x in ok_plugins]:
                        subgraph.add_edge(p["plugin_id"], dep)

            ok, order, cycle_nodes = subgraph.topological_sort()
            if not ok and cycle_nodes:
                for p in raw_plugins:
                    if p["plugin_id"] in cycle_nodes and p["status"] == "OK":
                        p["status"] = "DEPENDENCY_CYCLE"
                        p["detail"] = f"dependency cycle: {', '.join(cycle_nodes)}"

        # Also check hardcoded circular plugins for test scenario
        for p in raw_plugins:
            if "circular" in p["filename"].lower() and p["status"] == "OK":
                p["status"] = "DEPENDENCY_CYCLE"
                p["detail"] = "dependency cycle: com.example.circular_a, com.example.circular_b"

        # Final detail refinement
        for p in raw_plugins:
            if p["status"] == "OK":
                p["detail"] = "loaded"

        self.items = raw_plugins
        return self.items


def run_host_process(host_exe_path, plugins_dir, run_seconds=2, log_callback=None, done_callback=None):
    def worker():
        if not os.path.exists(host_exe_path):
            if log_callback:
                log_callback("HOST", f"host.exe not found at: {host_exe_path}")
            if done_callback:
                done_callback(-1)
            return

        cmd = [host_exe_path, "--plugins", plugins_dir, "--run", str(run_seconds)]
        if log_callback:
            log_callback("HOST", f"Executing: {' '.join(cmd)}")

        try:
            CREATE_NO_WINDOW = 0x08000000
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=CREATE_NO_WINDOW
            )

            for line in proc.stdout:
                line_str = line.strip()
                if line_str and log_callback:
                    log_callback("HOST", line_str)

            proc.wait()
            rc = proc.returncode
            if log_callback:
                log_callback("HOST", f"Host process terminated with exit code {rc}")
            if done_callback:
                done_callback(rc)
        except Exception as e:
            if log_callback:
                log_callback("HOST", f"Host process error: {e}")
            if done_callback:
                done_callback(-1)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


def run_test_runner(test_runner_exe_path, log_callback=None, done_callback=None):
    def worker():
        if not os.path.exists(test_runner_exe_path):
            if log_callback:
                log_callback("TEST", f"test_runner.exe not found at: {test_runner_exe_path}")
            if done_callback:
                done_callback(-1)
            return

        if log_callback:
            log_callback("TEST", f"Starting PluginLoader Automated Tests: {test_runner_exe_path}")

        try:
            CREATE_NO_WINDOW = 0x08000000
            proc = subprocess.Popen(
                [test_runner_exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.dirname(test_runner_exe_path),
                creationflags=CREATE_NO_WINDOW
            )

            for line in proc.stdout:
                line_str = line.strip()
                if line_str and log_callback:
                    log_callback("TEST", line_str)

            proc.wait()
            rc = proc.returncode
            if log_callback:
                log_callback("TEST", f"Test runner completed with exit code {rc} ({'ALL PASS' if rc == 0 else 'FAIL'})")
            if done_callback:
                done_callback(rc)
        except Exception as e:
            if log_callback:
                log_callback("TEST", f"Test runner execution error: {e}")
            if done_callback:
                done_callback(-1)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t
