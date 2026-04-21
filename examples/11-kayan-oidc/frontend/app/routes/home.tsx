import { useState } from "react";

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loginWithKayan() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/oidc/start");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      // Redirect to Kayan's authorization endpoint
      window.location.href = data.redirect_url;
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div>
      <h1>Login with Kayan OIDC</h1>
      <p>This application uses a Kayan instance as an OIDC Identity Provider.</p>
      <p style={{ fontSize: "0.85em", color: "#666" }}>
        Set <code>KAYAN_ISSUER</code>, <code>CLIENT_ID</code>, <code>CLIENT_SECRET</code> env vars on the backend.
        This demo simulates the token exchange without a real Kayan server.
      </p>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <button onClick={loginWithKayan} disabled={loading}>
        {loading ? "Redirecting to Kayan…" : "Login with Kayan"}
      </button>
    </div>
  );
}
