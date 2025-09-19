import { Elysia } from "elysia";

const app = new Elysia()
  .get("/", () => "Hello from OICD-Server")
  .listen(3000);

console.log(
  `🔐 OICD-Server started on port ${app.server?.hostname}:${app.server?.port}`,
);
