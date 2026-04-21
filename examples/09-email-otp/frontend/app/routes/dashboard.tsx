import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Dashboard() {
  const [email, setEmail] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("session_token");
    if (!token) { navigate("/"); return; }
    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(data => { if (data.error) navigate("/"); else setEmail(data.email); });
  }, [navigate]);

  return (
    <div>
      <h1>Dashboard</h1>
      {email ? <p>Logged in as <strong>{email}</strong></p> : <p>Loading…</p>}
      <button onClick={() => { localStorage.removeItem("session_token"); navigate("/"); }}>Logout</button>
    </div>
  );
}
