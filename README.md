# rn-pdf-decrypt

React Native compatible PDF decryption with **AES-256** and **RC4** support. Fork of [@pdfsmaller/pdf-decrypt](https://www.npmjs.com/package/@pdfsmaller/pdf-decrypt) that replaces Web Crypto API with [@noble/hashes](https://www.npmjs.com/package/@noble/hashes) + [@noble/ciphers](https://www.npmjs.com/package/@noble/ciphers) for Hermes compatibility.

## Why this fork?

The original `@pdfsmaller/pdf-decrypt` uses `crypto.subtle` (Web Crypto API), which is not available in React Native's Hermes engine. This fork swaps in pure JS crypto from the audited `@noble` libraries, making it work in React Native, Hermes, browsers, Node.js 18+, and Deno.

Additionally, this fork adds support for **AES-256 V=5/R=5** (Adobe's pre-ISO extension used by Acrobat X/XI), which the upstream package does not support.

## Features

- **AES-256 decryption** (V=5, R=5/6) — PDF 2.0 standard + Adobe extension
- **RC4 40/128-bit decryption** (V=1-2, R=2-3) — legacy support
- **User + Owner passwords** — accepts either password to decrypt
- **React Native / Hermes compatible** — no Web Crypto API dependency
- **Pure JS crypto** — `@noble/hashes` + `@noble/ciphers` (audited, zero-dep)
- **Lightweight** — ~18KB total (crypto + decryption logic)
- **TypeScript types** included

## Installation

```bash
npm install rn-pdf-decrypt
```

## Quick Start

```javascript
import { decryptPDF } from 'rn-pdf-decrypt';
import fs from 'fs';

const pdfBytes = fs.readFileSync('encrypted.pdf');
const decrypted = await decryptPDF(new Uint8Array(pdfBytes), 'my-password');
fs.writeFileSync('decrypted.pdf', decrypted);
```

## API

### `decryptPDF(pdfBytes, password)`

Decrypt a password-protected PDF. Supports both AES-256 and RC4 encryption — the algorithm is detected automatically.

| Parameter | Type | Description |
|-----------|------|-------------|
| `pdfBytes` | `Uint8Array` | The encrypted PDF file as bytes |
| `password` | `string` | The user or owner password |

**Returns:** `Promise<Uint8Array>` — The decrypted PDF bytes

**Throws:**
- `"This PDF is not encrypted"` — if the PDF has no encryption dictionary
- `"Incorrect password"` — if neither user nor owner password matches
- `"Unsupported encryption"` — if the encryption version is not supported

### `isEncrypted(pdfBytes)`

Check if a PDF is encrypted without attempting to decrypt it.

| Parameter | Type | Description |
|-----------|------|-------------|
| `pdfBytes` | `Uint8Array` | The PDF file as bytes |

**Returns:** `Promise<{ encrypted: boolean, algorithm?: 'AES-256' | 'RC4', version?: number, revision?: number, keyLength?: number }>`

## Examples

### Decrypt with Auto-Detection

```javascript
import { decryptPDF, isEncrypted } from 'rn-pdf-decrypt';

// Check encryption type first
const info = await isEncrypted(pdfBytes);
if (info.encrypted) {
  console.log(`Encrypted with ${info.algorithm}`);
  const decrypted = await decryptPDF(pdfBytes, password);
}
```

### React Native Usage

```javascript
import { decryptPDF } from 'rn-pdf-decrypt';
import RNFS from 'react-native-fs';

const base64 = await RNFS.readFile(filePath, 'base64');
const pdfBytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

const decrypted = await decryptPDF(pdfBytes, 'my-password');
```

## Supported Encryption

| Algorithm | PDF Version | Key Length | Status |
|-----------|-------------|-----------|--------|
| AES-256 (V=5, R=6) | 2.0 (ISO 32000-2) | 256-bit | Supported |
| AES-256 (V=5, R=5) | Adobe Extension Level 3 | 256-bit | Supported |
| RC4 (V=2, R=3) | 1.4+ (ISO 32000-1) | 128-bit | Supported |
| RC4 (V=1, R=2) | 1.1+ | 40-bit | Supported |
| AES-128 (V=4, R=4) | 1.6+ | 128-bit | Not yet supported |

## Differences from upstream

| | `@pdfsmaller/pdf-decrypt` | `rn-pdf-decrypt` |
|---|---|---|
| Crypto backend | Web Crypto API (`crypto.subtle`) | `@noble/hashes` + `@noble/ciphers` |
| React Native | No (Hermes lacks Web Crypto) | Yes |
| AES-256 V=5/R=5 | No | Yes |
| Dependencies | Zero (peer: pdf-lib) | `@noble/hashes`, `@noble/ciphers` (peer: pdf-lib) |

## License

MIT

Based on [@pdfsmaller/pdf-decrypt](https://www.npmjs.com/package/@pdfsmaller/pdf-decrypt) by [PDFSmaller.com](https://pdfsmaller.com).
