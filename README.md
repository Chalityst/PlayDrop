# PlayDrop
A self-hosted, AirDrop-style file transfer between your PC and iPhone over your local Wi‑Fi.

- No file size limit (streamed to/from disk, resumable downloads)
- HTTPS (self-signed cert) + per-run secret access key
- Upload from iPhone to PC, download from PC to iPhone, drag-and-drop on desktop
- Animated wave UI with chromatic aberration, light/dark mode

## Run
```
python playdrop.py [folder] [port]
```
Defaults: `./shared`, port `8765`. Open the printed `https://…/?k=…` link in Safari on the iPhone (same Wi‑Fi).
On first visit Safari warns about the self-signed certificate — tap **Show Details → visit this website**.
Compare the certificate fingerprint with the one printed on the PC.

Requires Python 3 and `openssl` (bundled with Git for Windows) to generate the certificate on first run.
