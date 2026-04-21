import { useState } from "react";
import { useNavigate } from "react-router";

export default function Home() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    const res = await fetch("/api/otp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    setLoading(false);
    if (!res.ok) { setError(data.error); return; }
    sessionStorage.setItem("otp_email", email);
    navigate("/verify");
  }

  return (
    <div>
      <h1>Email OTP Login</h1>
      <p>Enter your email to receive a 6-digit code (printed to server logs in this demo).</p>
      <form onSubmit={handleSubmit}>
        <div><label>Email<br /><input type="email" value={email} onChange={e => setEmail(e.target.value)} required style={{ width: "100%" }} /></label></div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit" disabled={loading}>{loading ? "Sending…" : "Send OTP"}</button>
      </form>
    </div>
  );
}
