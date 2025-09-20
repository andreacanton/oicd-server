import { Elysia } from "elysia";
import { core } from "./core";

const app = new Elysia()
  .use(core)
  .get("/", () => "Hello from OICD-Server")
  .listen(3000, ({ hostname, port }) => {
    console.info(`🔐 OICD-Server started on port http://${hostname}:${port}`);
  });
