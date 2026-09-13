import {
  json, handleCors, hashPassword, cryptoToken, getClientIp, getDevice,
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
    const password = String(body.password || "");
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!email || !password) return json(400, { error: "missing_fields" });

    const tooMany = await rateLimited(db, email, ip, "email");
    if (tooMany) {
      await db.from("login_logs").insert({ email, success: false, ip, device });
      return json(429, { error: "too_many_attempts" });
    }

    const { data: acc } = await db.from("accounts")
      .select("uid,email,name,role,approved,banned,salt,hash")
      .eq("email", email)
      .maybeSingle();

    const fail = async (error: string, status = 401) => {
      await db.from("login_attempts").insert({ email, ip, success: false });
      await db.from("login_logs").insert({ email, uid: acc?.uid ?? null, success: false, ip, device });
      return json(status, { error });
    };

    if (!acc) return await fail("auth_invalid");
    if (acc.banned) return await fail("banned", 403);
    if (!acc.approved && acc.role !== "admin") return await fail("access_blocked", 403);

    const hash = await hashPassword(password, acc.salt);
    if (hash !== acc.hash) return await fail("auth_invalid");

    const token = cryptoToken(32);
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const { error: se } = await db.from("sessions").insert({
      token, uid: acc.uid, expires_at: expires, device,
    });
    if (se) return handleError(se);
    await db.from("login_logs").insert({ email, uid: acc.uid, success: true, ip, device });

    return json(200, { token, uid: acc.uid, name: acc.name, role: acc.role });
  } catch (e) {
    return handleError(e);
  }
});