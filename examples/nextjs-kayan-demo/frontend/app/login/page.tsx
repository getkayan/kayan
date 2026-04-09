"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://localhost:4000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) throw new Error("Invalid credentials");
      
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    // Redirect to Go backend real OIDC initiation endpoint
    window.location.href = "http://localhost:4000/api/auth/google/login";
  };

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh" }}>
      <div className="glass-card" style={{ width: "100%", maxWidth: "480px" }}>
        <h1 className="title" style={{ fontSize: "1.75rem", textAlign: "center" }}>Welcome Back</h1>
        <p className="subtitle" style={{ textAlign: "center", fontSize: "0.875rem" }}>
          Choose your preferred secure entrance
        </p>

        <div className="social-links">
          <button onClick={handleGoogleLogin} className="btn btn-secondary" style={{ width: "100%", gap: "0.75rem" }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12.48 10.92v3.28h7.84c-.24 1.84-.908 3.152-1.928 4.176-1.228 1.224-3.136 2.592-6.44 2.592-5.46 0-9.8-4.456-9.8-9.92 0-5.464 4.34-9.92 9.8-9.92 3.1 0 5.4 1.228 7.156 2.896l2.316-2.316C19.04 1.052 16.144 0 12.48 0 5.612 0 0 5.568 0 12s5.612 12 12.48 12c3.756 0 6.6-1.228 8.8-3.484 2.16-2.16 2.84-5.26 2.84-7.78 0-.64-.04-1.24-.12-1.816H12.48z"/>
            </svg>
            Continue with Google
          </button>
          
          <button onClick={() => alert("SSO integration configured via core/saml")} className="btn btn-secondary" style={{ width: "100%", gap: "0.75rem" }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            Enterprise Single Sign-On
          </button>
        </div>

        <div className="divider">
          <span>or use email</span>
        </div>

        <form onSubmit={handlePasswordLogin}>
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
            <label>Secret Password</label>
            <input 
              type="password" 
              placeholder="••••••••" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {error && <p style={{ color: "#ef4444", fontSize: "0.75rem", marginBottom: "1rem" }}>{error}</p>}

          <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: "100%" }}>
            {loading ? "Verifying..." : "Access Identity"}
          </button>
        </form>

        <p style={{ marginTop: "2rem", textAlign: "center", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
          Don&apos;t have a vault yet? <Link href="/register" style={{ color: "var(--primary)", textDecoration: "none" }}>Initiate Creation</Link>
        </p>
      </div>
    </div>
  );
}
