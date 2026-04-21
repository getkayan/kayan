// Dashboard: shows authenticated user from GET /api/me.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

interface Me { id: string; email: string }

export default function Dashboard() {
  const navigate = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { navigate("/"); return; }

    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => {
        if (data.error) { setError(data.error); localStorage.removeItem("token"); }
        else setMe(data);
      })
      .catch(() => setError("Network error"));
  }, [navigate]);

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Dashboard</h1>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {me ? (
        <>
          <p>Logged in as <strong>{me.email}</strong></p>
          <button onClick={() => { localStorage.removeItem("token"); navigate("/"); }}>Logout</button>
        </>
      ) : !error && <p>Loading…</p>}
    </main>
  );
}
