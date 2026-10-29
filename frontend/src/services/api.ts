import type {
  ScanResponse,
  ApiError,
  BankingSystemProfile,
  BankingRiskAssessment,
  WhatIfMigrationRequest,
  WhatIfMigrationResult,
} from '../types/scan';

const API_BASE = import.meta.env.VITE_API_URL || '';

export async function scanDomain(
  domain: string,
  port: number = 443,
  probe_pqc: boolean = false,
  asset_id?: string
): Promise<ScanResponse> {
  const url = `${API_BASE}/api/scan`;
  const payload = { domain, port, probe_pqc, ...(asset_id ? { asset_id } : {}) };

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
  } catch (err: any) {
    // If proxied fetch failed (e.g. backend running on :8000 directly), retry direct URL
    try {
      response = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
    } catch {
      throw new Error(`Unable to connect to QuantumShield assessment backend. Please verify backend is running on http://127.0.0.1:8000.`);
    }
  }

  if (!response.ok) {
    let errorData: ApiError;
    try {
      errorData = await response.json();
    } catch {
      throw new Error(`Server returned error HTTP ${response.status}: ${response.statusText}`);
    }
    const message = errorData.detail || errorData.error || `Scan failed with HTTP ${response.status}`;
    throw new Error(message);
  }

  return response.json();
}

export async function getBankingProfiles(): Promise<BankingSystemProfile[]> {
  const url = `${API_BASE}/api/banking/profiles`;

  let response: Response;
  try {
    response = await fetch(url);
  } catch (err: any) {
    try {
      response = await fetch('http://127.0.0.1:8000/api/banking/profiles');
    } catch {
      throw new Error(`Unable to fetch banking profiles from http://127.0.0.1:8000/api/banking/profiles.`);
    }
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch banking profiles: HTTP ${response.status}`);
  }

  return response.json();
}

export async function getBankingProfileById(id: string): Promise<BankingSystemProfile> {
  const url = `${API_BASE}/api/banking/profiles/${encodeURIComponent(id)}`;

  let response: Response;
  try {
    response = await fetch(url);
  } catch (err: any) {
    try {
      response = await fetch(`http://127.0.0.1:8000/api/banking/profiles/${encodeURIComponent(id)}`);
    } catch {
      throw new Error(`Unable to fetch profile ${id} from backend.`);
    }
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch profile ${id}: HTTP ${response.status}`);
  }

  return response.json();
}

export async function getBankingRiskRankings(): Promise<BankingRiskAssessment[]> {
  const url = `${API_BASE}/api/banking/risk`;

  let response: Response;
  try {
    response = await fetch(url);
  } catch (err: any) {
    try {
      response = await fetch('http://127.0.0.1:8000/api/banking/risk');
    } catch {
      throw new Error(`Unable to fetch banking risk rankings from http://127.0.0.1:8000/api/banking/risk.`);
    }
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch banking risk rankings: HTTP ${response.status}`);
  }

  return response.json();
}

export async function getBankingProfileRisk(id: string): Promise<BankingRiskAssessment> {
  const url = `${API_BASE}/api/banking/profiles/${encodeURIComponent(id)}/risk`;

  let response: Response;
  try {
    response = await fetch(url);
  } catch (err: any) {
    try {
      response = await fetch(`http://127.0.0.1:8000/api/banking/profiles/${encodeURIComponent(id)}/risk`);
    } catch {
      throw new Error(`Unable to fetch risk assessment for profile ${id}.`);
    }
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch risk for profile ${id}: HTTP ${response.status}`);
  }

  return response.json();
}

export async function simulateMigration(
  request: WhatIfMigrationRequest
): Promise<WhatIfMigrationResult> {
  const url = `${API_BASE}/api/banking/risk/what-if`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });
  } catch (err: any) {
    try {
      response = await fetch('http://127.0.0.1:8000/api/banking/risk/what-if', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });
    } catch {
      throw new Error('Unable to connect to QuantumShield migration simulation service.');
    }
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.detail || `Migration simulation failed with HTTP ${response.status}`
    );
  }

  return response.json();
}

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) return true;
  } catch {
    // Retry direct port
    try {
      const res2 = await fetch('http://127.0.0.1:8000/api/health');
      return res2.ok;
    } catch {
      return false;
    }
  }
  return false;
}
