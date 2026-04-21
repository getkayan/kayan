// Verify page: reads ?token= from URL, calls GET /api/magic/verify, stores session.
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

export default function Verify() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get("token");
    if (!token) {
      setError("No token in URL");
      return;
    }

    // Call the backend to verify the magic-link token.
    fetch(`/api/magic/verify?token=${encodeURIComponent(token)}`)
      .then((r) => r.json())
      .then((data) => {
        if (data.error) {
          setError(data.error);
        } else {
          // Store session token and go to dashboard.
          localStorage.setItem("token", data.session_token);
          navigate("/dashboard");
        }
      })
      .catch(() => setError("Network error"));
  }, [searchParams, navigate]);

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 400, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Verifying magic link…</h1>
      {error ? <p style={{ color: "red" }}>{error}</p> : <p>Please wait…</p>}
    </main>
  );
}
