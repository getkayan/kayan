// TOTP Enroll: get secret from backend, display otpauth URI for authenticator apps.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function TOTPEnroll() {
  const navigate = useNavigate();
  const [secret, setSecret] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("partial_token");
    if (!token) { navigate("/login"); return; }

    fetch("/api/totp/enroll", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.error) setError(data.error);
        else { setSecret(data.secret); setUri(data.otpauth_uri); }
      })
      .catch(() => setError("Network error"));
  }, [navigate]);

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Enroll TOTP (Step 2a)</h1>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {secret && (
        <>
          <p>Scan this secret with your authenticator app (Google Authenticator, Authy, etc.):</p>
          <pre style={{ background: "#f0f0f0", padding: "0.5rem", wordBreak: "break-all" }}>{secret}</pre>
          <p><small>otpauth URI: <code>{uri}</code></small></p>
          <button onClick={() => navigate("/totp/confirm")}>I've added it — Confirm</button>
        </>
      )}
    </main>
  );
}
