import { Links, Meta, Outlet, Scripts, ScrollRestoration } from "react-router";
export default function Root() {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <Meta /><Links />
        <title>Kayan Example — Email OTP</title>
      </head>
      <body style={{ fontFamily: "system-ui, sans-serif", maxWidth: 480, margin: "40px auto", padding: "0 16px" }}>
        <Outlet />
        <ScrollRestoration /><Scripts />
      </body>
    </html>
  );
}
