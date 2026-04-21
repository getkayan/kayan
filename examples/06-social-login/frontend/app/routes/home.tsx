import { useState } from "react";

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loginWithGitHub() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/oauth/github/start");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      // Redirect browser to GitHub OAuth page
      window.location.href = data.redirect_url;
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div>
      <h1>Social Login — GitHub OAuth2</h1>
      <p>Click below to log in with your GitHub account.</p>
      <p style={{ fontSize: "0.85em", color: "#666" }}>
        Set <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code> env vars on the backend.
      </p>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <button onClick={loginWithGitHub} disabled={loading}>
        {loading ? "Redirecting…" : "Login with GitHub"}
      </button>
    </div>
  );
}
