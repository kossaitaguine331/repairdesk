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
    const email = url.searchParams.get("email");

    let q = db.from("login_logs")
      .select("success,ip,device,attempted_at")
      .order("attempted_at", { ascending: false })
      .limit(100);
    if (uid) q = q.eq("uid", uid);
    else if (email) q = q.eq("email", (email || "").toLowerCase());

    const { data, error } = await q;
    if (error) return handleError(error);
    return json(200, data || []);
  } catch (e) {
    return handleError(e);
  }
});