import { json, handleCors } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
  return json(200, { status: "ok" });
});