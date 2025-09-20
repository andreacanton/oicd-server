import { Elysia } from "elysia";

const app = new Elysia()
  .get("/", () => "Hello from OICD-Server")
  .listen(3000, ({ hostname, port }) => {
    console.info(`🔐 OICD-Server started on port http://${hostname}:${port}`);
  });
