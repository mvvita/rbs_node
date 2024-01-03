# Realizacija propusta CWE-296: Improper Following of a Certificate's Chain of Trust

Realizovali studenti:

- Kristina Todorović 2023/3441
- Marko Vitiz 2023/3168

Fajl `main.js` sadrži ispravnu realizaciju čitanja lanca X.509 sertifikata (ne i kompletnu, pokriveni su svi propusti koji su opisani u ovom projektu).

Neispravni kodovi svih propusta nalaze se u `weakness` folderu.
Pokretanje svih primera je potrebno izvršiti iz root foldera repozitorijuma, jer su putanje relativne (na primer, `node weakness/weakness_1.js`).
Za lakše uočavanje propusta u kodu, dovoljno je pretražiti svaki fajl za ključnu reč "PROPUST".
