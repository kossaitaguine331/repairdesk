import {
  json, handleCors, hashPassword, makeSalt, cryptoToken, getClientIp, getDevice,
  createDb, rateLimited, handleError,
} from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const name = String(body.name || "").trim();
    const password = String(body.password || "");
    const confirm = String(body.confirmPassword || "");
    const code = String(body.code || "").trim();
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });
    if (name.length === 0) return json(400, { error: "full_name_required" });
    if (password.length < 6) return json(400, { error: "auth_password_short" });
    if (password !== confirm) return json(400, { error: "auth_password_mismatch" });

    const tooMany = await rateLimited(db, "", ip, "ip");
    if (tooMany) return json(429, { error: "too_many_attempts" });

    const { data: existing } = await db.from("accounts").select("uid").eq("email", email).maybeSingle();
    if (existing) return json(400, { error: "auth_exists" });

    const redeem = async () => {
      const { data, error } = await db.rpc("redeem_access_code", { p_email: email, p_code: code });
      if (error || !data || data.length === 0) return false;
      return true;
    };
    if (!(await redeem())) {
      await db.from("login_attempts").insert({ email, ip, success: false });
      return json(400, { error: "access_code_invalid" });
    }

    const salt = makeSalt();
    const hash = await hashPassword(password, salt);
    const uid = "u" + Date.now().toString(36) + cryptoToken(4);
    const { error: ie } = await db.from("accounts").insert({
      uid, email, name, salt, hash, role: "user", approved: true, approved_at: new Date().toISOString(),
    });
    if (ie) return handleError(ie);

    const token = cryptoToken(32);
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const { error: se } = await db.from("sessions").insert({ token, uid, expires_at: expires, device });
    if (se) return handleError(se);
    await db.from("login_logs").insert({ email, uid, success: true, ip, device });

    return json(200, { token, uid, name, role: "user" });
  } catch (e) {
    return handleError(e);
  }
});