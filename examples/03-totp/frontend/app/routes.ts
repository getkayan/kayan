import { type RouteConfig, index, route } from "@react-router/dev/routes";

export default [
  index("routes/home.tsx"),
  route("register", "routes/register.tsx"),
  route("login", "routes/login.tsx"),
  route("totp/enroll", "routes/totp-enroll.tsx"),
  route("totp/confirm", "routes/totp-confirm.tsx"),
  route("dashboard", "routes/dashboard.tsx"),
] satisfies RouteConfig;
