"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function Dashboard() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    fetch("http://localhost:4000/api/auth/me", { credentials: "include" })
      .then((res) => {
        if (!res.ok) throw new Error("Unauthorized");
        return res.json();
      })
      .then((data) => setUser(data))
      .catch(() => router.push("/login"))
      .finally(() => setLoading(false));
  }, [router]);

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh" }}>
      <p className="subtitle">Synchronizing Identity...</p>
    </div>
  );

  const traits = user?.traits ? JSON.parse(Buffer.from(user.traits, 'base64').toString()) : {};

  return (
    <div className="container" style={{ padding: "4rem 2rem" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4rem" }}>
        <div>
          <h1 className="title" style={{ fontSize: "2rem", marginBottom: "0.25rem" }}>Vault Dashboard</h1>
          <p className="subtitle">Secure session active for {traits.email}</p>
        </div>
        <button onClick={() => { document.cookie = "kayan_session=; Max-Age=0"; router.push("/login"); }} className="btn btn-secondary">
          Decouple Access
        </button>
      </header>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "2rem" }}>
        <div className="glass-card" style={{ padding: "2rem" }}>
          <div style={{ width: "80px", height: "80px", borderRadius: "50%", background: "linear-gradient(135deg, var(--primary), var(--secondary))", marginBottom: "1.5rem" }}></div>
          <h2 style={{ fontSize: "1.25rem", marginBottom: "0.5rem" }}>Unified Profile</h2>
          <p style={{ opacity: 0.6, fontSize: "0.875rem", marginBottom: "2rem" }}>Your identity has been unified across all authentication vectors.</p>
          
          <div style={{ spaceY: "1rem" }}>
            <div style={{ marginBottom: "1rem" }}>
              <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", display: "block" }}>IDENTIFIER</span>
              <code style={{ fontSize: "0.875rem", color: "var(--primary)" }}>{user.id}</code>
            </div>
          </div>
        </div>

        <div className="glass-card" style={{ padding: "2rem" }}>
          <h2 style={{ fontSize: "1.25rem", marginBottom: "1.5rem" }}>Identity Traits</h2>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2rem" }}>
            {Object.entries(traits).map(([key, value]: [string, any]) => (
              <div key={key}>
                <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", display: "block", textTransform: "uppercase" }}>{key}</span>
                <span style={{ fontWeight: 600 }}>{String(value)}</span>
              </div>
            ))}
            <div>
              <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", display: "block", textTransform: "uppercase" }}>STATUS</span>
              <span style={{ color: "#22c55e", fontWeight: 600 }}>● Active</span>
            </div>
          </div>

          <div className="divider" style={{ margin: "2rem 0" }}>
            <span>Verified Connections</span>
          </div>

          <div style={{ display: "flex", gap: "1rem" }}>
             <div style={{ padding: "1rem", borderRadius: "12px", background: "rgba(255,255,255,0.05)", display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#22c55e" }}></div>
                <span style={{ fontSize: "0.875rem" }}>Email/Password</span>
             </div>
             <div style={{ padding: "1rem", borderRadius: "12px", background: "rgba(255,255,255,0.05)", display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#22c55e" }}></div>
                <span style={{ fontSize: "0.875rem" }}>Google OIDC</span>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
