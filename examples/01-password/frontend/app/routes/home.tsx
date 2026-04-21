// Home/landing page for the 01-password example.
import { Link } from "react-router";

export default function Home() {
  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 480, margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Kayan — Password Auth Example</h1>
      <p>Demonstrates bcrypt-based password authentication (register, login, protected route).</p>
      <nav style={{ display: "flex", gap: "1rem", marginTop: "2rem" }}>
        <Link to="/register">Register</Link>
        <Link to="/login">Login</Link>
        <Link to="/dashboard">Dashboard</Link>
      </nav>
    </main>
  );
}
