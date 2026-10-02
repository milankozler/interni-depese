// Sestavení šifrovaného archivu Interních depeší.
//   node depese.mjs build   depese.json + template.html -> index.html
//   node depese.mjs extract index.html -> depese.json (dešifruje publikovanou verzi)
// Heslo: proměnná DEPESE_HESLO, výchozí 112112.
// depese.json je otevřený text — do repozitáře nepatří (.gitignore).
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as c } from "node:crypto";

const HESLO = process.env.DEPESE_HESLO || "112112";
const ITER = 600000;
const b64e = (u) => Buffer.from(u).toString("base64");
const b64d = (t) => new Uint8Array(Buffer.from(t, "base64"));

async function klic(salt, iter) {
  const z = await c.subtle.importKey("raw", new TextEncoder().encode(HESLO), "PBKDF2", false, ["deriveKey"]);
  return c.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, z,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const cmd = process.argv[2];
if (cmd === "build") {
  const data = JSON.parse(readFileSync("depese.json", "utf8"));
  data.forEach((d, i) => {
    for (const k of ["cislo", "datum", "komu", "titulek", "telo"]) if (d[k] === undefined) throw new Error(`Depeše #${i} nemá ${k}`);
  });
  const salt = c.getRandomValues(new Uint8Array(16));
  const iv = c.getRandomValues(new Uint8Array(12));
  const ct = await c.subtle.encrypt({ name: "AES-GCM", iv }, await klic(salt, ITER), new TextEncoder().encode(JSON.stringify(data)));
  const payload = JSON.stringify({ iter: ITER, salt: b64e(salt), iv: b64e(iv), ct: b64e(ct) });
  const t = readFileSync("template.html", "utf8");
  if (!t.includes("__PAYLOAD__")) throw new Error("template.html bez __PAYLOAD__");
  writeFileSync("index.html", t.replace("__PAYLOAD__", payload));
  console.log(`index.html: ${data.length} čísel, viditelná: ${data.filter((d) => !d.skryto).map((d) => d.cislo).join(", ")}`);
} else if (cmd === "extract") {
  const h = readFileSync("index.html", "utf8");
  const p = JSON.parse(h.match(/const PAYLOAD = (\{.*?\});/)[1]);
  const pt = await c.subtle.decrypt({ name: "AES-GCM", iv: b64d(p.iv) }, await klic(b64d(p.salt), p.iter), b64d(p.ct));
  writeFileSync("depese.json", new TextDecoder().decode(pt));
  console.log("depese.json obnoven z index.html");
} else {
  console.log("použití: node depese.mjs build | extract");
}
