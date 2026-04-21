// Register passkey: begin → finish (simulated — no real WebAuthn browser API call).
// In production use navigator.credentials.create() with the challenge from the server.
import { useState } from "react";
import { useNavigate, Link } from "react-router";

export default function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setStatus(null);
    setLoading(true);

    try {
      // Step 1: Begin — server returns challenge + user info.
      const beginRes = await fetch("/api/webauthn/register/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const beginData = await beginRes.json();
      if (!beginRes.ok) { setError(beginData.error ?? "Begin failed"); return; }

      setStatus("Got challenge from server. Simulating authenticator response…");

      // In production: call navigator.credentials.create({ publicKey: beginData })
      // and send the resulting attestation object to the finish endpoint.
      const mockCredentialId = `mock-cred-${crypto.randomUUID()}`;

      // Step 2: Finish — send mock credential to server.
      const finishRes = await fetch("/api/webauthn/register/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, credential: { id: mockCredentialId } }),
      });
      const finishData = await finishRes.json();
      if (!finishRes.ok) { setError(finishData.error ?? "Finish failed"); return; }

      setStatus("Passkey registered! Redirecting to login…");
      setTimeout(() => navigate("/login"), 1500);
    } catch { setError("Network error"); }
    finally { setLoading(false); }
  }

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 400, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Register Passkey</h1>
      <form onSubmit={handleRegister} style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        {error && <p style={{ color: "red" }}>{error}</p>}
        {status && <p style={{ color: "blue" }}>{status}</p>}
        <button type="submit" disabled={loading}>{loading ? "Registering…" : "Register Passkey"}</button>
      </form>
      <p><Link to="/login">Already registered? Login</Link></p>
    </main>
  );
}
