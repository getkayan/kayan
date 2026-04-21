import { useState } from "react";
import { Link } from "react-router";

export default function Test() {
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [key, setKey] = useState(localStorage.getItem("api_key") ?? "");

  async function testKey() {
    setError("");
    setResult(null);
    const res = await fetch("/api/resource", {
      headers: { Authorization: `Bearer ${key}` },
    });
    const data = await res.json();
    if (!res.ok) setError(data.error);
    else setResult(data);
  }

  return (
    <div>
      <h1>Test API Key</h1>
      <Link to="/">← Back to key management</Link>
      <div style={{ marginTop: 16 }}>
        <input
          value={key}
          onChange={e => setKey(e.target.value)}
          placeholder="Paste API key (kayan_...)"
          style={{ width: "100%", marginBottom: 8, fontFamily: "monospace" }}
        />
        <button onClick={testKey}>Send request to /api/resource</button>
      </div>
      {error && <p style={{ color: "red" }}>Error: {error}</p>}
      {result && (
        <div style={{ background: "#f0fff0", border: "1px solid #5cb85c", padding: 12, marginTop: 8 }}>
          <strong>Response:</strong>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
