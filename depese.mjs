// Sestavení šifrovaného archivu Interních depeší.
//   node depese.mjs build             depese.json + template.html -> index.html
//   node depese.mjs extract           index.html -> depese.json (dešifruje publikovanou verzi)
//   node depese.mjs komentare r.json  dešifruje řádky z tabulky depese_komentare
//                                     (JSON pole {id, depese, iv, ct, created_at}) kvůli moderaci
// Heslo: proměnná DEPESE_HESLO, výchozí 112112.
// depese.json je otevřený text — do repozitáře nepatří (.gitignore).
//
// Schéma klíčů (musí sedět s template.html):
//   heslo -> PBKDF2-SHA256 (sůl SUL z template.html, 600 000 iterací) -> 256 bitů
//         -> HKDF-SHA256 info "depese-obsah"     -> AES-GCM klíč obsahu
//         -> HKDF-SHA256 info "depese-komentare" -> AES-GCM klíč komentářů (AAD "depese-<číslo>")
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as c } from "node:crypto";

const HESLO = process.env.DEPESE_HESLO || "112112";
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (u) => Buffer.from(u).toString("base64");
const b64d = (t) => new Uint8Array(Buffer.from(t, "base64"));

function nastaveniZeSablony() {
  const t = readFileSync("template.html", "utf8");
  return {
    t,
    sul: t.match(/const SUL = "([^"]+)"/)[1],
    iter: Number(t.match(/const ITERACE = (\d+)/)[1]),
  };
}

async function klice() {
  const { sul, iter } = nastaveniZeSablony();
  const z = await c.subtle.importKey("raw", enc.encode(HESLO), "PBKDF2", false, ["deriveBits"]);
  const bity = await c.subtle.deriveBits({ name: "PBKDF2", salt: b64d(sul), iterations: iter, hash: "SHA-256" }, z, 256);
  const hk = await c.subtle.importKey("raw", bity, "HKDF", false, ["deriveKey"]);
  const odvod = (info) => c.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
    hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { obsah: await odvod("depese-obsah"), komentare: await odvod("depese-komentare") };
}

// Původní schéma (do 2. 10. 2026): PBKDF2 přímo na AES klíč, sůl v PAYLOAD.
async function stareDesifrovani(p) {
  const z = await c.subtle.importKey("raw", enc.encode(HESLO), "PBKDF2", false, ["deriveKey"]);
  const k = await c.subtle.deriveKey({ name: "PBKDF2", salt: b64d(p.salt), iterations: p.iter, hash: "SHA-256" }, z,
    { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return c.subtle.decrypt({ name: "AES-GCM", iv: b64d(p.iv) }, k, b64d(p.ct));
}

const cmd = process.argv[2];
if (cmd === "build") {
  const data = JSON.parse(readFileSync("depese.json", "utf8"));
  const cisla = new Set();
  data.forEach((d, i) => {
    for (const k of ["cislo", "datum", "komu", "titulek", "telo"]) if (d[k] === undefined) throw new Error(`Depeše #${i} nemá ${k}`);
    if (cisla.has(d.cislo)) throw new Error(`Číslo ${d.cislo} je tam dvakrát`);
    cisla.add(d.cislo);
  });
  const { t } = nastaveniZeSablony();
  if (!t.includes("__PAYLOAD__")) throw new Error("template.html bez __PAYLOAD__");
  const iv = c.getRandomValues(new Uint8Array(12));
  const ct = await c.subtle.encrypt({ name: "AES-GCM", iv }, (await klice()).obsah, enc.encode(JSON.stringify(data)));
  writeFileSync("index.html", t.replace("__PAYLOAD__", JSON.stringify({ v: 2, iv: b64e(iv), ct: b64e(ct) })));
  console.log(`index.html: ${data.length} čísel, viditelná: ${data.filter((d) => !d.skryto).map((d) => d.cislo).join(", ")}`);
} else if (cmd === "extract") {
  const p = JSON.parse(readFileSync("index.html", "utf8").match(/const PAYLOAD = (\{.*?\});/)[1]);
  const pt = p.v === 2
    ? await c.subtle.decrypt({ name: "AES-GCM", iv: b64d(p.iv) }, (await klice()).obsah, b64d(p.ct))
    : await stareDesifrovani(p);
  writeFileSync("depese.json", dec.decode(pt));
  console.log("depese.json obnoven z index.html");
} else if (cmd === "komentare") {
  const radky = JSON.parse(readFileSync(process.argv[3], "utf8"));
  const k = (await klice()).komentare;
  for (const r of radky) {
    try {
      const pt = await c.subtle.decrypt({ name: "AES-GCM", iv: b64d(r.iv), additionalData: enc.encode("depese-" + r.depese) }, k, b64d(r.ct));
      const o = JSON.parse(dec.decode(pt));
      console.log(`#${r.id} | č. ${r.depese} | ${r.created_at} | ${o.j || "anonym"}${r.skryto ? " | SKRYTO" : ""}\n  ${o.t}`);
    } catch (e) {
      console.log(`#${r.id} | č. ${r.depese} | nejde dešifrovat (cizí nebo poškozený záznam)`);
    }
  }
} else if (cmd === "zasifruj-komentar") {
  // Pomocník pro testy: node depese.mjs zasifruj-komentar <cislo> <jmeno> <text>
  const [n, j, tx] = process.argv.slice(3);
  const iv = c.getRandomValues(new Uint8Array(12));
  const ct = await c.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("depese-" + n) },
    (await klice()).komentare, enc.encode(JSON.stringify({ j, t: tx })));
  console.log(JSON.stringify({ depese: Number(n), iv: b64e(iv), ct: b64e(ct) }));
} else {
  console.log("použití: node depese.mjs build | extract | komentare <radky.json> | zasifruj-komentar <cislo> <jmeno> <text>");
}
