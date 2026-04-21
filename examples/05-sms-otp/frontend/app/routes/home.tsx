import { useState } from "react";
import { useNavigate } from "react-router";

export default function Home() {
  const [phone, setPhone] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/sms/initiate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      // Pass phone to verify page via sessionStorage
      sessionStorage.setItem("otp_phone", phone);
      navigate("/verify");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1>SMS OTP Login</h1>
      <p>Enter your phone number to receive a one-time code (printed to server logs in this demo).</p>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Phone number<br />
            <input
              type="tel"
              value={phone}
              onChange={e => setPhone(e.target.value)}
              placeholder="+1234567890"
              required
              style={{ width: "100%", marginTop: 4 }}
            />
          </label>
        </div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit" disabled={loading} style={{ marginTop: 8 }}>
          {loading ? "Sending…" : "Send OTP"}
        </button>
      </form>
    </div>
  );
}
