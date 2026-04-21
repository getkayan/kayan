import { useState } from "react";
import { useNavigate } from "react-router";

export default function Verify() {
  const email = sessionStorage.getItem("otp_email") ?? "";
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch("/api/otp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    localStorage.setItem("session_token", data.session_token);
    navigate("/dashboard");
  }

  return (
    <div>
      <h1>Enter OTP</h1>
      <p>Check the server logs for the 6-digit code sent to <strong>{email}</strong>.</p>
      <form onSubmit={handleSubmit}>
        <div>
          <label>6-digit code<br />
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              value={code}
              onChange={e => setCode(e.target.value)}
              required
              style={{ letterSpacing: "0.3em", fontSize: "1.4em", width: "100%" }}
            />
          </label>
        </div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit">Verify</button>
      </form>
    </div>
  );
}
