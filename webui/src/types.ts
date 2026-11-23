export type Severity = "high" | "medium" | "low" | "info";
export type ReviewStatus = "open" | "fixed" | "accepted_risk" | "false_positive";
export type SectionId = "web" | "auth" | "infra" | "tls" | "maildns" | "vulns";

export interface Session {
  version: string;
  language: string;
  passive_modes: string[];
  modes: Record<string, string[]>;
  review_statuses: ReviewStatus[];
  database: string;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  created_at: string;
  target_count?: number;
  audit_count?: number;
  last_audit?: string | null;
}

export interface Target {
  id: number;
  project_id: number;
  value: string;
  kind: "domain" | "ip" | "url";
  note: string;
  created_at: string;
  audit_count?: number;
  last_audit?: string | null;
}

export type Counts = Record<Severity, number>;

export interface Audit {
  id: number;
  project_id: number;
  target_id: number | null;
  target: string;
  mode: string;
  report_date: string;
  created_at: string;
  grade: string | null;
  score: number | null;
  security: number | null;
  coverage: number | null;
  confidence: number | null;
  counts?: Counts;
  checks?: string[];
  previous_id?: number | null;
}

export interface Finding {
  id: number;
  audit_id: number;
  key: string;
  ext_id: string;
  target: string;
  path: string;
  category: string;
  section: SectionId;
  title: string;
  severity: Severity;
  evidence_status: string;
  confidence: string;
  evidence: string;
  tool: string;
  impact: string;
  verification: string;
  recommendation: string;
  references: string[];
  review_status: ReviewStatus;
  updated_at: string;
  priority: number;
}

export interface HistoryEvent {
  id: number;
  finding_id: number | null;
  key: string;
  audit_id: number | null;
  old_status: ReviewStatus | null;
  new_status: ReviewStatus;
  note: string;
  author: string;
  created_at: string;
  title?: string;
  target?: string;
  severity?: Severity;
}

export interface TrendPoint {
  id: number;
  date: string;
  score: number | null;
  security: number | null;
}

export interface Overview {
  projects: number;
  targets: number;
  audits: number;
  latest: Audit[];
  open_by_severity: Counts;
  open_by_section: Record<SectionId, number>;
  by_review_status: Record<ReviewStatus, number>;
  trend: { target: string; audit_id: number; previous_id: number | null; history: TrendPoint[] }[];
}

export interface Fact {
  label: string;
  value: string;
  tone: "good" | "bad" | "neutral";
}

export interface SectionData {
  section: SectionId;
  facts: { target: string; audit_id: number; date: string; mode: string; facts: Fact[] }[];
  findings: Finding[];
}

export interface Job {
  id: number;
  project_id: number;
  target_id: number;
  target: string;
  mode: string;
  state: "queued" | "running" | "cancelling" | "cancelled" | "done" | "error";
  module: string | null;
  progress: number;
  total: number;
  audit_id: number | null;
  error: string | null;
  created_at: number;
  finished_at: number | null;
}

export interface Comparison {
  base: Audit;
  head: Audit;
  comparable: boolean;
  reason: string;
  new: Finding[];
  fixed: Finding[];
  unchanged: Finding[];
  score_delta: number | null;
  security_delta: number | null;
}

export interface ToolInfo {
  name: string;
  category: string;
  available: boolean;
  minimum: string;
  install: string;
  path?: string;
  version?: string | null;
  compatible?: boolean | null;
  reason?: string;
  error?: string;
}
