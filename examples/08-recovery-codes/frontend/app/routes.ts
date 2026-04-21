import { type RouteConfig, index, route } from "@react-router/dev/routes";
export default [
  index("routes/home.tsx"),
  route("register", "routes/register.tsx"),
  route("login", "routes/login.tsx"),
  route("recovery-codes/setup", "routes/recovery-setup.tsx"),
  route("recover", "routes/recover.tsx"),
  route("dashboard", "routes/dashboard.tsx"),
] satisfies RouteConfig;
