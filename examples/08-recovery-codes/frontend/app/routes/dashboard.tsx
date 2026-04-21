import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Dashboard() {
  const [user, setUser] = useState<{ id: string; email: string } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("session_token");
    if (!token) { navigate("/"); return; }
    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(data => { if (data.error) navigate("/"); else setUser(data); });
  }, [navigate]);

  function logout() {
    localStorage.removeItem("session_token");
    navigate("/");
  }

  return (
    <div>
      <h1>Dashboard</h1>
      {user ? <p>Logged in as <strong>{user.email}</strong> (id: {user.id})</p> : <p>Loading…</p>}
      <button onClick={logout}>Logout</button>
    </div>
  );
}
