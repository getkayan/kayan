import Link from "next/link";

export default function Home() {
  return (
    <div className="container" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "100vh", textAlign: "center" }}>
      <h1 className="title" style={{ fontSize: "4rem" }}>Kayan Identity</h1>
      <p className="subtitle" style={{ fontSize: "1.25rem", maxWidth: "600px" }}>
        The headless IAM framework for high-growth teams. 
        Experience seamless account linking and identity unification.
      </p>
      
      <div style={{ display: "flex", gap: "1rem" }}>
        <Link href="/login" className="btn btn-primary" style={{ padding: "1rem 2rem", fontSize: "1.125rem" }}>
          Experience Demo
        </Link>
        <Link href="https://github.com/getkayan/kayan" className="btn btn-secondary" style={{ padding: "1rem 2rem", fontSize: "1.125rem" }}>
          GitHub Repository
        </Link>
      </div>

      <div style={{ marginTop: "4rem", display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "2rem", width: "100%" }}>
        <div className="glass-card" style={{ padding: "2rem" }}>
          <h3 style={{ marginBottom: "0.5rem" }}>Headless</h3>
          <p style={{ opacity: 0.6, fontSize: "0.875rem" }}>Complete control over your UI and user experience.</p>
        </div>
        <div className="glass-card" style={{ padding: "2rem" }}>
          <h3 style={{ marginBottom: "0.5rem" }}>Unified</h3>
          <p style={{ opacity: 0.6, fontSize: "0.875rem" }}>Social, SSO, and Passwords mapped to one Identity.</p>
        </div>
        <div className="glass-card" style={{ padding: "2rem" }}>
          <h3 style={{ marginBottom: "0.5rem" }}>BYOS</h3>
          <p style={{ opacity: 0.6, fontSize: "0.875rem" }}>Bring Your Own Schema. No rigid database locks.</p>
        </div>
      </div>
    </div>
  );
}
