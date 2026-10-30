import type { HealthResponse, ScanRecord, ScanSummary, StatsResponse } from "../types/scan";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (response.status === 204) {
    return undefined as T;
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    const message =
      typeof detail === "string"
        ? detail
        : detail?.message || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return data as T;
}

export function createScan(body: {
  url: string;
  save_history: boolean;
  allow_external_intel: boolean;
}) {
  return request<ScanRecord>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getScan(id: string) {
  return request<ScanRecord>(`/api/v1/scans/${id}`);
}

export function listScans() {
  return request<{ items: ScanSummary[]; total: number }>("/api/v1/scans");
}

export function deleteScan(id: string) {
  return request<void>(`/api/v1/scans/${id}`, { method: "DELETE" });
}

export function clearScans() {
  return request<void>("/api/v1/scans", { method: "DELETE" });
}

export function getStats() {
  return request<StatsResponse>("/api/v1/stats");
}

export function getHealth() {
  return request<HealthResponse>("/api/v1/health");
}
