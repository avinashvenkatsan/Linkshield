import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTimestamp(value?: string | null) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

export function classificationLabel(value: string) {
  switch (value) {
    case "high":
      return "High Risk";
    case "medium":
      return "Medium Risk";
    case "low":
      return "Low Risk";
    default:
      return "Unknown / Incomplete";
  }
}
