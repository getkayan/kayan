import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

interface Me { id: string; email: string; totp_enrolled: boolean }

export default function Dashboard() {
  const navigate = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { navigate("/login"); return; }
    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => { if (data.error) setError(data.error); else setMe(data); })
      .catch(() => setError("Network error"));
  }, [navigate]);

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Dashboard</h1>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {me && (
        <>
          <p>Email: <strong>{me.email}</strong></p>
          <p>TOTP enrolled: <strong>{me.totp_enrolled ? "Yes" : "No"}</strong></p>
          <button onClick={() => { localStorage.removeItem("token"); navigate("/login"); }}>Logout</button>
        </>
      )}
      {!me && !error && <p>Loading…</p>}
    </main>
  );
}
