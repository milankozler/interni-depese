# Interní depeše

Archiv interního newsletteru Eintopf s.r.o. Obsah je zašifrovaný (PBKDF2 + AES-GCM), stránka ho dešifruje až po zadání hesla.

- `template.html` – vzhled a logika stránky, bez obsahu
- `depese.mjs` – `node depese.mjs extract` dešifruje `index.html` do `depese.json`, `node depese.mjs build` ho zase zašifruje
- `depese.json` je otevřený text a do repozitáře se necommituje
