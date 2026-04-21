import { useState } from "react";
import { useNavigate, Link } from "react-router";

export default function RecoverySetup() {
  const [codes, setCodes] = useState<string[]>([]);
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const partialToken = sessionStorage.getItem("partial_token") ?? "";

  async function generate() {
    setError("");
    const res = await fetch("/api/recovery-codes/generate", {
      method: "POST",
      headers: { Authorization: `Bearer ${partialToken}` },
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    setCodes(data.codes);
  }

  return (
    <div>
      <h1>Setup Recovery Codes</h1>
      <p>Generate 10 single-use recovery codes. Store them somewhere safe — they won't be shown again.</p>
      <button onClick={generate}>Generate Recovery Codes</button>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {codes.length > 0 && (
        <div>
          <h2>Your Recovery Codes (save these!)</h2>
          <div style={{ background: "#f5f5f5", padding: 12, fontFamily: "monospace" }}>
            {codes.map((c, i) => <div key={i}>{c}</div>)}
          </div>
          <p>Once saved, <Link to="/recover">use one to complete login →</Link></p>
        </div>
      )}
    </div>
  );
}
