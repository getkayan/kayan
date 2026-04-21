import { useEffect, useState } from "react";
import { Link } from "react-router";

type KeyRecord = { id: string; name: string; created_at: string };

export default function Home() {
  const [name, setName] = useState("");
  const [newKey, setNewKey] = useState("");
  const [apiKey, setApiKey] = useState(localStorage.getItem("api_key") ?? "");
  const [keys, setKeys] = useState<KeyRecord[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function loadKeys() {
    if (!apiKey) return;
    const res = await fetch("/api/keys/", { headers: { Authorization: `Bearer ${apiKey}` } });
    const data = await res.json();
    if (Array.isArray(data)) setKeys(data);
  }

  useEffect(() => { loadKeys(); }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  async function generate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setNewKey("");
    try {
      const res = await fetch("/api/keys/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setNewKey(data.key);
      // Use the first generated key as the working key
      if (!apiKey) {
        localStorage.setItem("api_key", data.key);
        setApiKey(data.key);
      }
      await loadKeys();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function revoke(id: string) {
    await fetch(`/api/keys/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    await loadKeys();
  }

  function useKey() {
    const k = prompt("Paste your API key:");
    if (k) {
      localStorage.setItem("api_key", k);
      setApiKey(k);
    }
  }

  return (
    <div>
      <h1>API Key Management</h1>
      <p>Current key: <code>{apiKey ? apiKey.slice(0, 20) + "…" : "(none)"}</code></p>
      <button onClick={useKey} style={{ marginRight: 8 }}>Use existing key</button>
      <Link to="/test"><button>Test key against /api/resource →</button></Link>

      <h2>Generate New Key</h2>
      <form onSubmit={generate}>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="Key name (e.g. my-service)"
          required
          style={{ width: "100%", marginBottom: 8 }}
        />
        <button type="submit" disabled={loading}>{loading ? "Generating…" : "Generate"}</button>
      </form>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {newKey && (
        <div style={{ background: "#fffbe6", border: "1px solid #f0ad4e", padding: 12, marginTop: 8 }}>
          <strong>Copy this key — it will NOT be shown again:</strong>
          <pre style={{ wordBreak: "break-all" }}>{newKey}</pre>
        </div>
      )}

      <h2>Your Keys</h2>
      {keys.length === 0 ? <p>No keys yet.</p> : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr><th align="left">ID</th><th align="left">Name</th><th align="left">Created</th><th></th></tr></thead>
          <tbody>
            {keys.map(k => (
              <tr key={k.id}>
                <td><code>{k.id}</code></td>
                <td>{k.name}</td>
                <td>{new Date(k.created_at).toLocaleString()}</td>
                <td><button onClick={() => revoke(k.id)}>Revoke</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
