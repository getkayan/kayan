import { Link } from "react-router";
export default function Home() {
  return (
    <div>
      <h1>LDAP Authentication</h1>
      <p>Demonstrates login via LDAP directory (simulated). In production uses <code>github.com/go-ldap/ldap/v3</code> with TLS.</p>
      <p>Pre-populated users: <code>alice / alice123</code>, <code>bob / bob456</code></p>
      <Link to="/login"><button>Login with LDAP →</button></Link>
    </div>
  );
}
