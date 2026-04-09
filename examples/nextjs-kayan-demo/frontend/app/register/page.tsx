"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const router = useRouter();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://localhost:4000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.message || "Registration failed");
      }
      
      setSuccess(true);
      setTimeout(() => router.push("/login"), 2000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh" }}>
      <div className="glass-card" style={{ width: "100%", maxWidth: "480px" }}>
        <h1 className="title" style={{ fontSize: "1.75rem", textAlign: "center" }}>Initiate Creation</h1>
        <p className="subtitle" style={{ textAlign: "center", fontSize: "0.875rem" }}>
          Forge your unique identity vault
        </p>

        {success ? (
          <div style={{ textAlign: "center", padding: "2rem" }}>
            <div style={{ color: "#22c55e", fontSize: "1.25rem", marginBottom: "1rem" }}>Vault Successfully Forged</div>
            <p className="subtitle">Redirecting to entrance...</p>
          </div>
        ) : (
          <form onSubmit={handleRegister}>
            <div className="input-group">
              <label>Email Address</label>
              <input 
                type="email" 
                placeholder="name@company.com" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            
            <div className="input-group">
              <label>Password Directive</label>
              <input 
                type="password" 
                placeholder="Create strong secret" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && <p style={{ color: "#ef4444", fontSize: "0.75rem", marginBottom: "1rem" }}>{error}</p>}

            <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: "100%" }}>
              {loading ? "Forging..." : "Create Vault"}
            </button>
          </form>
        )}

        <p style={{ marginTop: "2rem", textAlign: "center", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
          Already have a vault? <Link href="/login" style={{ color: "var(--primary)", textDecoration: "none" }}>Access Entrance</Link>
        </p>
      </div>
    </div>
  );
}
