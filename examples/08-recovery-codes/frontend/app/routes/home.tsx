import { Link } from "react-router";
export default function Home() {
  return (
    <div>
      <h1>Recovery Codes MFA</h1>
      <p>Demonstrates single-use MFA fallback codes (bcrypt-hashed on the server).</p>
      <ol>
        <li><Link to="/register">Register</Link> — create account</li>
        <li><Link to="/login">Login</Link> — password login returns partial token</li>
        <li>Generate recovery codes (shown once)</li>
        <li><Link to="/recover">Recover</Link> — use a code to complete login</li>
      </ol>
    </div>
  );
}
