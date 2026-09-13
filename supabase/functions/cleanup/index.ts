import { json, handleCors, createDb, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  const db = createDb();
  const { error } = await db.rpc("cleanup_old_logs");
  if (error) return handleError(error);
  return json(200, { success: true });
});