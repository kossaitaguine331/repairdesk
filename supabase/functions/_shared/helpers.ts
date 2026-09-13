// Shared helpers for RepairDesk auth Edge Functions.
// All functions import { ... } from "../_shared/helpers.ts".

import { createClient } from "jsr:@supabase/supabase-js@2";

const CLIENT_URL = Deno.env.get("ALLOWED_ORIGIN") || "https://kossaitaguine331.github.io";
const DB_URL = Deno.env.get("SUPABASE_URL") || "";

export const corsHeaders = {
  "Access-Control-Allow-Origin": CLIENT_URL,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Vary": "Origin",
};

function isAllowedOrigin(origin: string): boolean {
  return origin === CLIENT_URL;
}

export function json(status: number, body: unknown): Response {
  const payload = JSON.stringify(body);
  return new Response(payload, {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

export function handleCors(req: Request): Response | null {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") {
    if (origin && !isAllowedOrigin(origin)) return json(403, { error: "origin_not_allowed" });
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  // Non-OPTIONS: if an Origin header is present it must be allowed;
  // requests with no Origin (curl, server-to-server keepalive) pass through.
  if (origin && !isAllowedOrigin(origin)) return json(403, { error: "origin_not_allowed" });
  return null;
}

export function cryptoToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function makeSalt(): string {
  return cryptoToken(16);
}

export async function hashPassword(pw: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(salt + "::" + pw);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function getClientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") || "unknown";
}

export function getDevice(req: Request): string {
  return (req.headers.get("user-agent") || "").slice(0, 300);
}

export function createDb() {
  // Deno + Supabase runtime auto-injects these env vars for edge functions.
  const url = DB_URL;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  return createClient(url, key, { auth: { persistSession: false } });
}

export async function rateLimited(db: any, email = "", ip = "", key = "email"): Promise<boolean> {
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const col = key === "ip" ? "ip" : "email";
  const value = key === "ip" ? ip : email;
  if (!value) return false;
  const { count, error } = await db
    .from("login_attempts")
    .select("id", { count: "exact", head: true })
    .eq(col, value)
    .eq("success", false)
    .gte("created_at", since);
  if (error) return false; // fail open on DB error to avoid full outage
  return (count || 0) >= 5;
}

export async function findSessionUser(db: any, token: string) {
  if (!token) return null;
  const { data } = await db
    .from("sessions")
    .select("uid, expires_at, accounts(uid, email, name, role, approved, banned)")
    .eq("token", token)
    .maybeSingle();
  return data ?? null;
}

export async function sessionOk(db: any, token: string) {
  const s = await findSessionUser(db, token);
  if (!s) return null;
  if (new Date(s.expires_at).getTime() < Date.now()) return null;
  if (!s.accounts) return null;
  if (s.accounts.banned || !s.accounts.approved) return null;
  return s;
}

export async function requireAdmin(req: Request, db: any): Promise<Response | { account: any; token: string } | null> {
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const s = await sessionOk(db, token);
  if (!s) return json(401, { error: "unauthorized" });
  if ((s as any).accounts?.role !== "admin") return json(403, { error: "forbidden" });
  return { account: (s as any).accounts, token };
}

export function handleError(e: unknown): Response {
  console.error(e);
  return json(500, { error: "server_error" });
}