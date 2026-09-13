import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const { data, error } = await db.from("accounts")
      .select("uid,email,name,approved,banned,created_at")
      .order("created_at", { ascending: true });
    if (error) return handleError(error);

    // last successful login per account
    const lastLogins: Record<string, string> = {};
    const { data: logs } = await db.from("login_logs")
      .select("uid,attempted_at")
      .eq("success", true)
      .order("attempted_at", { ascending: false });
    (logs || []).forEach((l: any) => { if (l.uid && !(l.uid in lastLogins)) lastLogins[l.uid] = l.attempted_at; });

    const out = (data || []).map((a: any) => ({
      uid: a.uid, email: a.email, name: a.name, approved: a.approved,
      banned: a.banned, created_at: a.created_at, last_login: lastLogins[a.uid] || null,
    }));
    return json(200, out);
  } catch (e) {
    return handleError(e);
  }
});