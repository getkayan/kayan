import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Callback() {
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");

    if (!code || !state) {
      // In the demo, the redirect from handleStart won't actually come back here
      // (no real Kayan server). Simulate a callback for demo purposes.
      fetch(`/api/oidc/callback?code=demo-code&state=demo-state`)
        .then(r => r.json())
        .then(data => {
          if (data.error) throw new Error(data.error);
          localStorage.setItem("session_token", data.session_token);
          navigate("/dashboard");
        })
        .catch((err: any) => setError(err.message || "Callback failed"));
      return;
    }

    fetch(`/api/oidc/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) throw new Error(data.error);
        localStorage.setItem("session_token", data.session_token);
        navigate("/dashboard");
      })
      .catch((err: any) => setError(err.message));
  }, [navigate]);

  return (
    <div>
      <h1>Completing OIDC login…</h1>
      {error ? <p style={{ color: "red" }}>{error}</p> : <p>Verifying identity with Kayan…</p>}
    </div>
  );
}
