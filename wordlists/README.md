# Wordlists

recon-engine does not vendor large wordlists in this repo. TBHM KB §14
names these sources directly — point `recon-engine scan --wordlist` at
whichever you pull down:

- **Assetnote wordlists**: https://wordlists.assetnote.io (subdomain
  bruteforce lists, kept updated)
- **trickest/resolvers**: https://github.com/trickest/resolvers —
  `resolvers.txt` / `resolvers-trusted.txt`, fetched automatically by
  `subdomain_bruteforce.fetch_resolvers()` if you don't supply your own.

```bash
curl -sL https://wordlists.assetnote.io/data/manual/best-dns-wordlist.txt -o words.txt
recon-engine scan example.com --bruteforce --wordlist words.txt --resolvers resolvers.txt
```
