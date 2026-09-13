import { json, handleCors, createDb, requireAdmin, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const url = new URL(req.url);
    const uid = url.searchParams.get("uid");
    let q = db.from("sessions")
      .select("token,device,created_at,last_seen_at,expires_at")
      .order("created_at", { ascending: false })
      .limit(100);
    if (uid) q = q.eq("uid", uid);
    const { data, error } = await q;
    if (error) return handleError(error);
    return json(200, (data || []).map((s: any) => ({
      token_id: s.token.slice(0, 8) + "â€¦",
      device: s.device,
      created_at: s.created_at,
      last_seen_at: s.last_seen_at,
      expires_at: s.expires_at,
    })));
  } catch (e) {
    return handleError(e);
  }
});