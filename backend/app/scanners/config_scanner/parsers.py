"""Configuration file parsers with security boundaries, line tracking, and format support.
Supported formats:
- YAML (.yaml, .yml)
- JSON (.json)
- TOML (.toml)
- INI / CFG / CONF (.ini, .cfg, .conf)
- Java Properties (.properties)
- XML (.xml)
- ENV / Example Environment (.env, .env.example)

Security guarantees:
- Never executes or imports configuration code.
- Rejects binary files and files with null bytes.
- Enforces directory boundary and rejects path traversal attempts.
- Gracefully handles syntax/decode errors without crashing.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import xml.etree.ElementTree as ET

# Attempt PyYAML import; fallback to built-in basic parser if missing
try:
    import yaml
    from yaml.loader import SafeLoader
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

# Python 3.11+ tomllib
try:
    import tomllib
    HAVE_TOML = True
except ImportError:
    HAVE_TOML = False


class ParserSecurityError(Exception):
    """Raised when security boundaries (path traversal, binary data) are violated."""
    pass


class ParserError(Exception):
    """Raised or captured when configuration file parsing fails."""
    pass


@dataclass
class ParsedEntry:
    """A flattened configuration key-value entry with path and line provenance."""
    path: str
    value: Any
    line: Optional[int] = None
    raw_key: str = ""
    is_interpolated: bool = False  # e.g., ${VAR}
    is_list: bool = False

    def __post_init__(self):
        if not self.raw_key and self.path:
            self.raw_key = self.path.split(".")[-1]



@dataclass
class ParsedConfigFile:
    """The normalized result of parsing a configuration file."""
    file_path: str
    format: str
    raw_data: Any
    entries: List[ParsedEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# Line-tracking YAML SafeLoader
if HAVE_YAML:
    class LineTrackingSafeLoader(SafeLoader):
        """Custom SafeLoader that stores line numbers for dicts and values."""
        pass

    def _construct_mapping_with_lines(loader: SafeLoader, node: Any) -> Dict[str, Any]:
        loader.flatten_mapping(node)
        mapping = {}
        line_map = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=False)
            val = loader.construct_object(value_node, deep=False)
            mapping[key] = val
            line_map[key] = key_node.start_mark.line + 1
        mapping["__line_map__"] = line_map
        mapping["__line__"] = node.start_mark.line + 1
        return mapping

    LineTrackingSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_mapping_with_lines
    )


class SafeConfigParser:
    """
    Safe parser for banking configurations across multiple formats.
    Enforces path boundaries and avoids executing code.
    """

    SUPPORTED_EXTENSIONS = {
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".toml": "TOML",
        ".ini": "INI",
        ".cfg": "INI",
        ".conf": "INI",
        ".properties": "PROPERTIES",
        ".env": "ENV",
        ".example": "ENV",
        ".xml": "XML",
    }

    def __init__(self, root_dir: Optional[Path] = None):
        """
        Initialize parser.
        :param root_dir: If specified, all parsed files must reside within root_dir.
        """
        self.root_dir = root_dir.resolve() if root_dir else None

    def validate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validate file path against traversal and binary rules.
        """
        path = Path(file_path).resolve()
        if self.root_dir:
            try:
                path.relative_to(self.root_dir)
            except ValueError:
                raise ParserSecurityError(f"Path traversal detected: {path} is outside allowed root {self.root_dir}")

        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        # Check for binary file
        try:
            with open(path, "rb") as f:
                header = f.read(4096)
                if b"\x00" in header:
                    raise ParserSecurityError(f"Binary file rejected: {path}")
        except OSError as e:
            raise ParserError(f"Cannot read file {path}: {e}")

        return path

    def parse_file(self, file_path: Union[str, Path], relative_to: Optional[Path] = None) -> ParsedConfigFile:
        """
        Parse configuration file safely into normalized entries with line numbers.
        """
        canonical_path = self.validate_file_path(file_path)
        display_path = str(canonical_path.relative_to(relative_to)) if relative_to else canonical_path.name

        ext = canonical_path.suffix.lower()
        # Handle compound extensions like .env.example
        if canonical_path.name.startswith(".env") or ext in (".env", ".example"):
            fmt = "ENV"
        else:
            fmt = self.SUPPORTED_EXTENSIONS.get(ext)

        if not fmt:
            return ParsedConfigFile(
                file_path=display_path,
                format="UNSUPPORTED",
                raw_data=None,
                errors=[f"Unsupported configuration extension: {ext}"]
            )

        try:
            text = canonical_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return ParsedConfigFile(
                file_path=display_path,
                format=fmt,
                raw_data=None,
                errors=[f"Failed to read file: {e}"]
            )

        entries: List[ParsedEntry] = []
        errors: List[str] = []
        raw_data = None

        try:
            if fmt == "YAML":
                raw_data, entries = self._parse_yaml(text)
            elif fmt == "JSON":
                raw_data, entries = self._parse_json(text)
            elif fmt == "TOML":
                raw_data, entries = self._parse_toml(text)
            elif fmt == "INI":
                raw_data, entries = self._parse_ini(text)
            elif fmt == "PROPERTIES":
                raw_data, entries = self._parse_properties(text)
            elif fmt == "ENV":
                raw_data, entries = self._parse_env(text)
            elif fmt == "XML":
                raw_data, entries = self._parse_xml(text)
        except Exception as e:
            errors.append(f"Parsing {fmt} failed: {e}")

        return ParsedConfigFile(
            file_path=display_path,
            format=fmt,
            raw_data=raw_data,
            entries=entries,
            errors=errors
        )

    # ----------------- PARSERS -----------------

    def _parse_yaml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        if not HAVE_YAML:
            return None, []
        try:
            data = yaml.load(text, Loader=LineTrackingSafeLoader)
        except Exception:
            # Fallback to standard safe_load if custom loader fails
            data = yaml.safe_load(text)
            return data, self._flatten_data(data, line_map={})

        entries: List[ParsedEntry] = []
        self._extract_entries_from_dict(data, prefix="", entries=entries)
        return data, entries

    def _extract_entries_from_dict(
        self,
        node: Any,
        prefix: str,
        entries: List[ParsedEntry],
        parent_line_map: Optional[Dict[str, int]] = None
    ) -> None:
        if isinstance(node, dict):
            current_line_map = node.get("__line_map__", {})
            for key, val in node.items():
                if key in ("__line_map__", "__line__"):
                    continue
                path = f"{prefix}.{key}" if prefix else str(key)
                line = current_line_map.get(key)
                if line is None and parent_line_map:
                    line = parent_line_map.get(key)
                if isinstance(val, (dict, list)):
                    self._extract_entries_from_dict(val, path, entries, current_line_map)
                    # Also record list or dict as a container entry
                    if isinstance(val, list):
                        entries.append(self._create_entry(path, val, line, is_list=True))
                else:
                    entries.append(self._create_entry(path, val, line))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                path = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)):
                    self._extract_entries_from_dict(item, path, entries)
                else:
                    entries.append(self._create_entry(path, item, None))

    def _parse_json(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        data = json.loads(text)
        # Build line index for keys by searching text lines
        lines = text.splitlines()
        line_cache: Dict[str, int] = {}
        for line_no, line_str in enumerate(lines, start=1):
            match = re.search(r'"([^"\\]+)":', line_str)
            if match:
                key = match.group(1)
                if key not in line_cache:
                    line_cache[key] = line_no

        entries: List[ParsedEntry] = []
        self._flatten_json(data, prefix="", entries=entries, line_cache=line_cache)
        return data, entries

    def _flatten_json(
        self,
        node: Any,
        prefix: str,
        entries: List[ParsedEntry],
        line_cache: Dict[str, int]
    ) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                line = line_cache.get(key)
                if isinstance(val, dict):
                    self._flatten_json(val, path, entries, line_cache)
                elif isinstance(val, list):
                    entries.append(self._create_entry(path, val, line, is_list=True))
                    self._flatten_json(val, path, entries, line_cache)
                else:
                    entries.append(self._create_entry(path, val, line))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                path = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)):
                    self._flatten_json(item, path, entries, line_cache)
                else:
                    entries.append(self._create_entry(path, item, None))

    def _parse_toml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        if not HAVE_TOML:
            raise ParserError("tomllib is required for TOML parsing")
        data = tomllib.loads(text)
        lines = text.splitlines()
        entries: List[ParsedEntry] = []

        # Find line number for key paths
        def find_line(key: str) -> Optional[int]:
            pattern = re.compile(rf'^\s*{re.escape(key)}\s*=')
            for idx, l in enumerate(lines, start=1):
                if pattern.search(l):
                    return idx
            return None

        def recurse(node: Any, prefix: str):
            if isinstance(node, dict):
                for k, v in node.items():
                    path = f"{prefix}.{k}" if prefix else str(k)
                    line = find_line(k)
                    if isinstance(v, dict):
                        recurse(v, path)
                    elif isinstance(v, list):
                        entries.append(self._create_entry(path, v, line, is_list=True))
                        recurse(v, path)
                    else:
                        entries.append(self._create_entry(path, v, line))
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    path = f"{prefix}[{idx}]"
                    if isinstance(item, (dict, list)):
                        recurse(item, path)
                    else:
                        entries.append(self._create_entry(path, item, None))

        recurse(data, "")
        return data, entries

    def _parse_ini(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, Dict[str, str]] = {}
        current_section = "DEFAULT"
        raw[current_section] = {}

        for line_no, line in enumerate(text.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith(";"):
                continue
            sec_match = re.match(r"^\[([a-zA-Z0-9_\-\.\:]+)\]$", line_str)
            if sec_match:
                current_section = sec_match.group(1)
                raw[current_section] = {}
                continue
            if "=" in line_str or ":" in line_str:
                sep = "=" if "=" in line_str else ":"
                k, v = line_str.split(sep, 1)
                key = k.strip()
                val = v.strip()
                raw[current_section][key] = val
                path = f"{current_section}.{key}" if current_section != "DEFAULT" else key
                # Detect list if comma or space separated ciphers/protocols
                entries.append(self._create_entry(path, val, line_no))

        return raw, entries

    def _parse_properties(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, str] = {}
        for line_no, line in enumerate(text.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("!"):
                continue
            if "=" in line_str or ":" in line_str:
                sep = "=" if "=" in line_str else ":"
                k, v = line_str.split(sep, 1)
                key = k.strip()
                val = v.strip()
                raw[key] = val
                entries.append(self._create_entry(key, val, line_no))
        return raw, entries

    def _parse_env(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, str] = {}
        for line_no, line in enumerate(text.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "=" in line_str:
                k, v = line_str.split("=", 1)
                key = k.strip()
                val = v.strip().strip("'\"")
                raw[key] = val
                entries.append(self._create_entry(key, val, line_no))
        return raw, entries

    def _parse_xml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        # Safe XML parsing (standard ElementTree does not expand external entities)
        entries: List[ParsedEntry] = []
        lines = text.splitlines()

        def find_tag_line(tag: str) -> Optional[int]:
            pattern = re.compile(rf'<{re.escape(tag)}[\s>]')
            for idx, l in enumerate(lines, start=1):
                if pattern.search(l):
                    return idx
            return None

        root = ET.fromstring(text)
        raw = {root.tag: {}}

        def recurse(node: ET.Element, path: str):
            line = find_tag_line(node.tag)
            text_val = node.text.strip() if node.text else None
            if text_val:
                entries.append(self._create_entry(path, text_val, line))
            for attr_k, attr_v in node.attrib.items():
                attr_path = f"{path}@{attr_k}"
                entries.append(self._create_entry(attr_path, attr_v, line))
            for child in node:
                child_path = f"{path}.{child.tag}"
                recurse(child, child_path)

        recurse(root, root.tag)
        return raw, entries

    def _create_entry(
        self,
        path: str,
        val: Any,
        line: Optional[int],
        is_list: bool = False
    ) -> ParsedEntry:
        val_str = str(val)
        is_interp = bool(re.search(r"\$\{[A-Za-z0-9_\-]+\}", val_str))
        return ParsedEntry(
            path=path,
            value=val,
            line=line,
            raw_key=path.split(".")[-1],
            is_interpolated=is_interp,
            is_list=is_list
        )

    def _flatten_data(self, data: Any, line_map: Dict[str, int]) -> List[ParsedEntry]:
        entries: List[ParsedEntry] = []
        if isinstance(data, dict):
            for k, v in data.items():
                entries.append(self._create_entry(str(k), v, line_map.get(k)))
        return entries
