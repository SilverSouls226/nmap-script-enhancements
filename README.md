# Custom Nmap Scripting Engine (NSE) Enhancements

**Course:** Cyber Security (Fall Semester 2026–2027, Slot F1)  
**Author:** Skandan Suresh  

---

## Overview

This repository maintains the source code for two custom enhancements developed for the Nmap Scripting Engine (NSE) as part of the Cyber Security laboratory assignment. The scripts extend base network auditing capabilities by introducing targeted protocol inspection and feature extraction logic under the HTTP protocol.

## Repository Contents

- `scripts/reference/http-headers.nse`: The baseline reference script that dumps raw HTTP response headers.
- `scripts/enhanced-script-1/http-page-assets.nse`: Enhancement 1 featuring DOM parsing to extract and categorize internal links, external domains, script tags, stylesheets, and media endpoints.
- `scripts/enhanced-script-2/http-method-matrix.nse`: Enhancement 2 featuring active multi-verb HTTP transport probing (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `TRACE`) and divergence detection against `Allow:` headers.
- `docs/USAGE.txt`: Plain-text CLI invocation parameters and syntax reference.

## Installation & Deployment

To deploy these scripts into your local Nmap script directory:

```bash
# Copy enhanced scripts to the default Nmap script directory
sudo cp scripts/enhanced-script-1/http-page-assets.nse /usr/share/nmap/scripts/
sudo cp scripts/enhanced-script-2/http-method-matrix.nse /usr/share/nmap/scripts/

# Update the Nmap script database index
sudo nmap --script-updatedb
```

Alternatively, copy them to your user Nmap scripts folder (does not require root):

```bash
mkdir -p ~/.nmap/scripts/
cp scripts/enhanced-script-1/http-page-assets.nse ~/.nmap/scripts/
cp scripts/enhanced-script-2/http-method-matrix.nse ~/.nmap/scripts/
nmap --script-updatedb
```

## Invocation Syntax

### Reference Script:
```bash
nmap -p 80 --script http-headers <target>
```

### Enhancement 1 (Asset & Resource Discovery):
```bash
nmap -p 80 --script http-page-assets <target>
```

Custom path parameter:
```bash
nmap -p 80 --script http-page-assets --script-args http-page-assets.path=/docs <target>
```

### Enhancement 2 (HTTP Method Capability Matrix):
```bash
nmap -p 80 --script http-method-matrix <target>
```

Custom methods or path:
```bash
nmap -p 80 --script http-method-matrix --script-args 'http-method-matrix.methods="GET POST PUT DELETE PATCH"' <target>
```

## License

This software is released under the standard Nmap Public Source License / GPL v2.
