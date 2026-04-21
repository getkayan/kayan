import { Link } from "react-router";

export default function Home() {
  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Kayan — TOTP (2FA) Example</h1>
      <p>Password + Time-based One-Time Password second factor. TOTP is computed inline (HMAC-SHA1, 30s, 6 digits).</p>
      <nav style={{ display: "flex", gap: "1rem", marginTop: "2rem" }}>
        <Link to="/register">Register</Link>
        <Link to="/login">Login</Link>
        <Link to="/dashboard">Dashboard</Link>
      </nav>
    </main>
  );
}
