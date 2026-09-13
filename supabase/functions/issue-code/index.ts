import { json, handleCors, createDb, requireAdmin, handleError, cryptoToken } from "../_shared/helpers.ts";

const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
function genCode(): string {
  const rand = crypto.getRandomValues(new Uint8Array(12));
  let s = "";
  for (let i = 0; i < 4; i++) {
    if (i) s += "-";
    let g = "";
    for (let j = 0; j < 3; j++) g += CODE_CHARS[rand[i * 3 + j] % CODE_CHARS.length];
    s += g;
  }
  return s; // XXX-XXX-XXX-XXX
}

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const note = String(body.note || "").slice(0, 200);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });

    const { data: existing } = await db.from("access_codes")
      .select("code")
      .eq("email", email)
      .eq("active", true)
      .eq("used", false)
      .maybeSingle();
    if (existing) return json(200, { code: existing.code, reused: true });

    const code = genCode();
    const { error } = await db.from("access_codes").insert({ email, code, note });
    if (error) return handleError(error);
    return json(200, { code, reused: false });
  } catch (e) {
    return handleError(e);
  }
});