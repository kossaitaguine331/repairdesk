import {
  json, handleCors, hashPassword, makeSalt, getClientIp, getDevice,
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
    const code = String(body.code || "").trim();
    const newPassword = String(body.newPassword || "");
    const confirm = String(body.confirmPassword || "");
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });
    if (newPassword.length < 6) return json(400, { error: "auth_password_short" });
    if (newPassword !== confirm) return json(400, { error: "auth_password_mismatch" });

    const tooMany = await rateLimited(db, email, ip, "email");
    if (tooMany) return json(429, { error: "too_many_attempts" });

    const { data: acc } = await db.from("accounts")
      .select("uid")
      .eq("email", email)
      .maybeSingle();
    if (!acc) return json(400, { error: "reset_no_account" });

    const salt = makeSalt();
    const hash = await hashPassword(newPassword, salt);
    const { data: uid, error } = await db.rpc("reset_with_access_code", {
      p_email: email, p_code: code, p_salt: salt, p_hash: hash,
    });
    if (error) {
      if (error.code === "P0001" && error.message === "reset_no_account") {
        return json(400, { error: "reset_no_account" });
      }
      if (error.code === "P0001" && error.message === "reset_code_invalid") {
        await db.from("login_attempts").insert({ email, ip, success: false });
        return json(400, { error: "reset_code_invalid" });
      }
      return handleError(error);
    }
    await db.from("login_logs").insert({ email, uid, success: true, ip, device });

    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});