import { useState } from "react";
import { useNavigate } from "react-router";

export default function Verify() {
  const phone = sessionStorage.getItem("otp_phone") ?? "";
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/sms/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      localStorage.setItem("session_token", data.session_token);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1>Enter your OTP</h1>
      <p>Check your phone (or server logs) for the 6-digit code sent to <strong>{phone}</strong>.</p>
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
              style={{ width: "100%", letterSpacing: "0.3em", fontSize: "1.4em", marginTop: 4 }}
            />
          </label>
        </div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit" disabled={loading} style={{ marginTop: 8 }}>
          {loading ? "Verifying…" : "Verify"}
        </button>
      </form>
    </div>
  );
}
