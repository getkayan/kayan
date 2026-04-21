import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Dashboard() {
  const [user, setUser] = useState<{ username: string; display_name: string; email: string } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("session_token");
    if (!token) { navigate("/"); return; }
    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(data => { if (data.error) navigate("/"); else setUser(data); });
  }, [navigate]);

  return (
    <div>
      <h1>Dashboard</h1>
      {user ? (
        <div>
          <p>Display Name: <strong>{user.display_name}</strong></p>
          <p>Username: <strong>{user.username}</strong></p>
          <p>Email: <strong>{user.email}</strong></p>
        </div>
      ) : <p>Loading…</p>}
      <button onClick={() => { localStorage.removeItem("session_token"); navigate("/"); }}>Logout</button>
    </div>
  );
}
