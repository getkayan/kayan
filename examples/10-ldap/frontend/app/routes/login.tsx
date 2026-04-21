import { useState } from "react";
import { useNavigate } from "react-router";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch("/api/ldap/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    localStorage.setItem("session_token", data.session_token);
    navigate("/dashboard");
  }

  return (
    <div>
      <h1>LDAP Login</h1>
      <p>Try <code>alice / alice123</code> or <code>bob / bob456</code></p>
      <form onSubmit={handleSubmit}>
        <div><label>Username<br /><input value={username} onChange={e => setUsername(e.target.value)} required style={{ width: "100%" }} /></label></div>
        <div><label>Password<br /><input type="password" value={password} onChange={e => setPassword(e.target.value)} required style={{ width: "100%" }} /></label></div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit">Login</button>
      </form>
    </div>
  );
}
