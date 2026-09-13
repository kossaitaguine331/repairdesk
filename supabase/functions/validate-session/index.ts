import { json, handleCors, createDb, findSessionUser, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const token = String(body.token || "");

    const s = await findSessionUser(db, token);
    if (!s || new Date(s.expires_at).getTime() < Date.now()) return json(200, { valid: false });
    const acc = s.accounts;
    if (!acc || acc.banned || !acc.approved) return json(200, { valid: false });

    const { error } = await db.from("sessions")
      .update({ last_seen_at: new Date().toISOString(), expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() })
      .eq("token", token);
    if (error) return handleError(error);

    return json(200, { valid: true, uid: acc.uid, name: acc.name, role: acc.role, banned: false });
  } catch (e) {
    return handleError(e);
  }
});