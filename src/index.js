export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        const result = await env.DB.prepare("SELECT 1 AS connected").first();
        return Response.json({
          ok: true,
          database: result?.connected === 1 ? "connected" : "unavailable",
          service: "Vestibular UniFil 2027"
        });
      } catch (error) {
        return Response.json({
          ok: false,
          database: "error",
          message: "Não foi possível consultar o banco de dados."
        }, { status: 503 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
