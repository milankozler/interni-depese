# Interní depeše

Archiv interního newsletteru Eintopf s.r.o. Obsah je zašifrovaný (PBKDF2 + AES-GCM), stránka ho dešifruje až po zadání hesla.

- `template.html` – vzhled a logika stránky, bez obsahu
- `depese.mjs` – `node depese.mjs extract` dešifruje `index.html` do `depese.json`, `node depese.mjs build` ho zase zašifruje
- `depese.json` je otevřený text a do repozitáře se necommituje

## Komentáře

Ukládají se do Supabase (projekt `ukoly`, tabulka `public.depese_komentare`), zašifrované klíčem odvozeným z hesla.
Anonym smí jen vkládat a číst neskryté řádky; měnit, mazat ani skrývat nemůže.

- Přečíst kvůli moderaci: vytáhnout řádky SQL (`select id, depese, iv, ct, created_at, skryto from depese_komentare`), uložit jako JSON a spustit `node depese.mjs komentare radky.json`.
- Skrýt: `update depese_komentare set skryto = true where id = …`

Sůl v `template.html` (`SUL`) se nesmí měnit — jinak přestanou jít přečíst všechny dosavadní komentáře.
