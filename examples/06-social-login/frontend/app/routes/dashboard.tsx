import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Dashboard() {
  const [user, setUser] = useState<{ login: string; email: string } | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("session_token");
    if (!token) { navigate("/"); return; }
    fetch("/api/me", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(data => {
        if (data.error) throw new Error(data.error);
        setUser(data);
      })
      .catch((err: any) => setError(err.message));
  }, [navigate]);

  function logout() {
    localStorage.removeItem("session_token");
    navigate("/");
  }

  return (
    <div>
      <h1>Dashboard</h1>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {user && (
        <div>
          <p>GitHub login: <strong>{user.login}</strong></p>
          <p>Email: <strong>{user.email || "(not public)"}</strong></p>
        </div>
      )}
      <button onClick={logout}>Logout</button>
    </div>
  );
}
