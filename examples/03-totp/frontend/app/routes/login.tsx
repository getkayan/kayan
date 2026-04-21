// Login: step 1 of 2. Password verification returns a partial_token.
// If TOTP is enrolled, user is redirected to TOTP verify page.
// If not enrolled, user is redirected to TOTP enroll page.
import { useState } from "react";
import { useNavigate, Link } from "react-router";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/login/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "Login failed"); return; }

      // Store partial token for the next step.
      localStorage.setItem("partial_token", data.partial_token);

      if (data.totp_enrolled) {
        // Step 2: verify existing TOTP
        navigate("/totp/confirm");
      } else {
        // TOTP not yet set up — enroll now
        navigate("/totp/enroll");
      }
    } catch { setError("Network error"); }
    finally { setLoading(false); }
  }

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 400, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Login (Step 1 — Password)</h1>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit" disabled={loading}>{loading ? "Checking…" : "Continue"}</button>
      </form>
      <p><Link to="/register">No account? Register</Link></p>
    </main>
  );
}
