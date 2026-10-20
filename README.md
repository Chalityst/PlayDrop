# PlayDrop
A self-hosted, AirDrop-style file transfer between your PC and iPhone over your local Wi‑Fi.

- No file size limit (streamed to/from disk, resumable downloads)
- Upload from iPhone to PC, download from PC to iPhone, drag-and-drop on desktop
- Animated wave UI with chromatic aberration, light/dark mode

## Run
```
python playdrop.py [folder] [port]
```
Defaults: `./shared`, port `8765`. Open the printed `http://…` link in Safari on the iPhone (same Wi‑Fi).

Requires only Python 3. Traffic is plain HTTP — anyone on the same Wi‑Fi can open it, so use it only on a network you trust.
