import { json, handleCors, createDb, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const token = String(body.token || "");
    if (token) await db.from("sessions").delete().eq("token", token);
    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});