// Login with passkey: begin → finish (simulated).
// In production use navigator.credentials.get() with the challenge from the server.
import { useState } from "react";
import { useNavigate, Link } from "react-router";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setStatus(null);
    setLoading(true);

    try {
      // Step 1: Begin — server returns challenge + allowCredentials list.
      const beginRes = await fetch("/api/webauthn/login/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const beginData = await beginRes.json();
      if (!beginRes.ok) { setError(beginData.error ?? "Begin failed"); return; }

      setStatus("Got challenge. Simulating authenticator assertion…");

      // In production: call navigator.credentials.get({ publicKey: { challenge, allowCredentials } })
      // The browser lets the user pick a passkey; you send the result to /login/finish.
      const credId = beginData.allowCredentials?.[0]?.id ?? "mock";

      // Step 2: Finish — send mock assertion.
      const finishRes = await fetch("/api/webauthn/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, assertion: { id: credId } }),
      });
      const finishData = await finishRes.json();
      if (!finishRes.ok) { setError(finishData.error ?? "Login failed"); return; }

      localStorage.setItem("token", finishData.session_token);
      navigate("/dashboard");
    } catch { setError("Network error"); }
    finally { setLoading(false); }
  }

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 400, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Login with Passkey</h1>
      <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        {error && <p style={{ color: "red" }}>{error}</p>}
        {status && <p style={{ color: "blue" }}>{status}</p>}
        <button type="submit" disabled={loading}>{loading ? "Authenticating…" : "Login with Passkey"}</button>
      </form>
      <p><Link to="/register">No passkey? Register</Link></p>
    </main>
  );
}
