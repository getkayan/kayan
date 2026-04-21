// TOTP Confirm / Verify: enter 6-digit code from authenticator.
// On first enroll: calls /api/totp/confirm then /api/login/totp.
// On subsequent logins: calls /api/login/totp directly.
import { useState } from "react";
import { useNavigate } from "react-router";

export default function TOTPConfirm() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const token = localStorage.getItem("partial_token");
    if (!token) { navigate("/login"); return; }

    try {
      // First, confirm enrollment (idempotent — only matters on first login after enroll).
      const confirmRes = await fetch("/api/totp/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code }),
      });
      const confirmData = await confirmRes.json();
      if (!confirmRes.ok) { setError(confirmData.error ?? "TOTP confirm failed"); return; }

      // Then complete the login to get a full session token.
      const loginRes = await fetch("/api/login/totp", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code }),
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) { setError(loginData.error ?? "TOTP login failed"); return; }

      localStorage.removeItem("partial_token");
      localStorage.setItem("token", loginData.session_token);
      navigate("/dashboard");
    } catch { setError("Network error"); }
    finally { setLoading(false); }
  }

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 400, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Enter TOTP Code (Step 2)</h1>
      <p>Enter the 6-digit code from your authenticator app.</p>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        <input
          type="text"
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          maxLength={6}
          required
          inputMode="numeric"
          pattern="\d{6}"
        />
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit" disabled={loading || code.length !== 6}>
          {loading ? "Verifying…" : "Verify"}
        </button>
      </form>
    </main>
  );
}
