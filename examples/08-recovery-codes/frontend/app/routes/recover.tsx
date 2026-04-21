import { useState } from "react";
import { useNavigate } from "react-router";

export default function Recover() {
  const email = sessionStorage.getItem("user_email") ?? "";
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch("/api/login/recover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, recovery_code: code }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    localStorage.setItem("session_token", data.session_token);
    navigate("/dashboard");
  }

  return (
    <div>
      <h1>Use Recovery Code</h1>
      <p>Enter one of your previously generated recovery codes.</p>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Recovery code (for {email || "your account"})<br />
            <input
              type="text"
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="paste recovery code here"
              required
              style={{ width: "100%", fontFamily: "monospace" }}
            />
          </label>
        </div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit">Complete Login</button>
      </form>
    </div>
  );
}
