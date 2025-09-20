import Elysia, { t } from "elysia";

const AuthorizeRequest = t.Object({
  request_type: t.Literal("code"),
  client_id: t.String(),
  redirect_uri: t.Optional(t.String()),
  scope: t.Optional(t.String()),
});
type AuthorizeRequest = typeof AuthorizeRequest.static;

export const core = new Elysia().get(
  "/authorize",
  async ({ query: AuthorizeRequest }) => {}
);
