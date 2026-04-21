import { useState } from "react";
import { useNavigate } from "react-router";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    sessionStorage.setItem("partial_token", data.partial_token);
    sessionStorage.setItem("user_email", email);
    navigate("/recovery-codes/setup");
  }

  return (
    <div>
      <h1>Login</h1>
      <p>After password login, you'll be prompted to generate or use recovery codes.</p>
      <form onSubmit={handleSubmit}>
        <div><label>Email<br /><input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label></div>
        <div><label>Password<br /><input type="password" value={password} onChange={e => setPassword(e.target.value)} required /></label></div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button type="submit">Login</button>
      </form>
    </div>
  );
}
