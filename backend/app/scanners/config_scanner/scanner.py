"""Banking configuration scanner orchestrator.
Inspects sample configuration directories, applies safe parsers and rules,
extracts cryptographic facts, and builds a normalized inventory.

SECURITY:
- Strictly treats configuration files as untrusted data.
- Read-only access; NEVER modifies or executes configuration files.
- Enforces boundary restrictions to prevent path traversal.
- Silently ignores binary files and handles corrupt configurations safely.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from app.scanners.config_scanner.evidence import EvidenceNormalizer
from app.scanners.config_scanner.models import (
    ConfigObservation,
    CryptoRole,
    NormalizedCryptoInventory,
)
from app.scanners.config_scanner.parsers import SafeConfigParser
from app.scanners.config_scanner.rules import ConfigRuleEngine


class BankingConfigScanner:
    """
    Deterministic configuration scanner for banking sample environments.
    """

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = root_dir.resolve() if root_dir else None
        self.parser = SafeConfigParser(root_dir=self.root_dir)

    def scan_file(
        self,
        file_path: Path,
        relative_to: Optional[Path] = None
    ) -> List[ConfigObservation]:
        """
        Scan a single configuration file and return extracted observations.
        Does not mutate the file.
        """
        parsed = self.parser.parse_file(file_path, relative_to=relative_to)
        if parsed.errors or not parsed.entries:
            return []

        rule_engine = ConfigRuleEngine(source_file=parsed.file_path)
        observations: List[ConfigObservation] = []

        for entry in parsed.entries:
            obs = rule_engine.evaluate_entry(entry)
            observations.extend(obs)

        # Sort observations deterministically by file, line, path, value
        observations.sort(key=lambda o: (o.file, o.line or 0, o.path, str(o.value)))
        return observations

    def scan_directory(
        self,
        dir_path: Path,
        system_id: Optional[str] = None,
        system_name: Optional[str] = None
    ) -> NormalizedCryptoInventory:
        """
        Scan all configuration files in a system directory and build a normalized inventory.
        """
        dir_path = Path(dir_path).resolve()
        default_id = system_id or f"BANK-SAMPLE-{dir_path.name.upper()}"
        default_name = system_name or f"Synthetic System ({dir_path.name})"

        all_observations: List[ConfigObservation] = []
        collected_metadata: Dict[str, Any] = {
            "system_id": default_id,
            "name": default_name,
        }

        # Recursively discover and scan supported config files
        # Sort files deterministically
        candidate_files: List[Path] = []
        for root, _, files in os.walk(dir_path):
            for f in sorted(files):
                file_p = Path(root) / f
                ext = file_p.suffix.lower()
                if ext in self.parser.SUPPORTED_EXTENSIONS or file_p.name.startswith(".env"):
                    candidate_files.append(file_p)

        candidate_files.sort(key=lambda p: str(p))

        for file_p in candidate_files:
            try:
                obs_list = self.scan_file(file_p, relative_to=dir_path)
                for obs in obs_list:
                    all_observations.append(obs)
                    # Harvest system metadata
                    if obs.role == CryptoRole.SYSTEM_METADATA and "meta_type" in obs.metadata:
                        m_type = obs.metadata["meta_type"]
                        if m_type == "system_id":
                            collected_metadata["system_id"] = str(obs.value)
                        elif m_type == "system_type":
                            collected_metadata["system_type"] = str(obs.value)
                        elif m_type in ("criticality", "trust_zone", "exposure", "data_sensitivity", "data_lifetime"):
                            collected_metadata[m_type] = str(obs.value)
            except Exception:
                # Handle individual file errors gracefully
                continue

        # Sort all observations deterministically
        all_observations.sort(key=lambda o: (o.file, o.line or 0, o.path, str(o.value)))

        normalizer = EvidenceNormalizer(
            system_id=collected_metadata.get("system_id", default_id),
            system_name=collected_metadata.get("name", default_name)
        )

        return normalizer.normalize(
            observations=all_observations,
            system_metadata=collected_metadata
        )

    def scan_all_banking_samples(
        self,
        base_dir: Path
    ) -> Dict[str, NormalizedCryptoInventory]:
        """
        Scan all subdirectories under backend/sample_data/banking/.
        Returns a mapping from system directory name to NormalizedCryptoInventory.
        """
        base_path = Path(base_dir).resolve()
        results: Dict[str, NormalizedCryptoInventory] = {}

        if not base_path.is_dir():
            return results

        # Sort subdirectories deterministically
        subdirs = sorted([d for d in base_path.iterdir() if d.is_dir()], key=lambda d: d.name)

        for subdir in subdirs:
            inv = self.scan_directory(subdir)
            results[subdir.name] = inv

        return results
