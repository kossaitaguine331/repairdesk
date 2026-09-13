import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const body = await req.json().catch(() => ({}));
    const targetUid = String(body.uid || "");
    const banned = Boolean(body.banned);
    if (!targetUid) return json(400, { error: "missing_fields" });
    if (targetUid === (auth as any).account.uid) return json(400, { error: "cannot_ban_self" });

    if (banned) {
      const { error } = await db.rpc("ban_user", { p_uid: targetUid });
      if (error) return handleError(error);
    } else {
      const { data, error } = await db.from("accounts").update({ banned: false }).eq("uid", targetUid).select("uid");
      if (error) return handleError(error);
      if (!data || data.length === 0) return json(404, { error: "not_found" });
    }
    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});