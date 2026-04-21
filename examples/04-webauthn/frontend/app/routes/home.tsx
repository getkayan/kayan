import { Link } from "react-router";

export default function Home() {
  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Kayan — WebAuthn / Passkey Example</h1>
      <p>Simulated FIDO2 passkey flow. Backend illustrates register/login ceremony shapes.</p>
      <p><em>In production, use <code>github.com/go-webauthn/webauthn</code> with real attestation + assertion verification.</em></p>
      <nav style={{ display: "flex", gap: "1rem", marginTop: "2rem" }}>
        <Link to="/register">Register Passkey</Link>
        <Link to="/login">Login with Passkey</Link>
        <Link to="/dashboard">Dashboard</Link>
      </nav>
    </main>
  );
}
