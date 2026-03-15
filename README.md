# Hash Collision Lab

Practical demonstration of MD5 and SHA-1 hash collision attacks using PDF files. Two visually different documents produce identical hash values, proving these algorithms are cryptographically broken.

> Built by [Innora AI](https://innora.ai) Security Research Lab

## Results

### SHA-1 Collision (SHAttered Attack Reproduction)

| File | SHA-1 | SHA-256 |
|------|-------|---------|
| `sha1-collision/innora-doc-A.pdf` | `4f5d1c...23c3e` | `8cc411...fe06c1` |
| `sha1-collision/innora-doc-B.pdf` | `4f5d1c...23c3e` | `1d5e7f...c1381b` |

**Same SHA-1, different SHA-256, different visual content.** 62 bytes differ.

### MD5 Collision (FastColl)

| File | MD5 | SHA-1 |
|------|-----|-------|
| `md5-collision/innora-doc-A.pdf` | `4da41e...32250` | `a3c1ef...44d80` |
| `md5-collision/innora-doc-B.pdf` | `4da41e...32250` | `e112a7...83034` |

**Same MD5, different SHA-1, different binary content.** 8 bytes differ. Generated in 0.2 seconds.

## Quick Verify

```bash
./verify.sh
```

Or manually:

```bash
# SHA-1 collision
shasum sha1-collision/innora-doc-A.pdf sha1-collision/innora-doc-B.pdf

# MD5 collision
md5sum md5-collision/innora-doc-A.pdf md5-collision/innora-doc-B.pdf  # Linux
md5 md5-collision/innora-doc-A.pdf md5-collision/innora-doc-B.pdf    # macOS
```

## How It Works

### SHA-1 Collision

Uses the [SHAttered](https://shattered.io/) technique (Stevens et al., 2017). The [sha1collider](https://github.com/nneonneo/sha1collider) tool takes two input PDFs, renders them as JPEGs, and embeds them into a specially crafted PDF structure with a known collision prefix. The collision block causes different image data to be referenced in each file while maintaining identical SHA-1 state.

```
PDF Header → Collision Block (differs) → JPEG Stream A or B → Trailer
                  ↕ same SHA-1 state after this block
```

### MD5 Collision

Uses [FastColl](https://github.com/brimstone/fastcoll) (Stevens, 2006) which implements an identical-prefix collision attack on MD5. Given a shared prefix, it finds two 128-byte suffix blocks that produce the same MD5 hash. The attack exploits differential paths in the MD5 compression function and runs in seconds on consumer hardware.

```
Shared PDF Prefix → Collision Block A (128 bytes) → Common Suffix
Shared PDF Prefix → Collision Block B (128 bytes) → Common Suffix
                         ↕ same MD5
```

## Attack Comparison

| Property | MD5 | SHA-1 | SHA-256 |
|----------|-----|-------|---------|
| Collision attack | 0.2 seconds | Hours (precomputed) | Infeasible |
| Chosen-prefix collision | Minutes | Days | Infeasible |
| Second preimage | Infeasible | Infeasible | Infeasible |
| Still used in practice | APK signing, legacy systems | Git (migrating), some CAs | Recommended standard |

## Real-World Impact

- **Flame malware (2012)**: Used MD5 chosen-prefix collision to forge a Microsoft code signing certificate
- **SHAttered (2017)**: Google/CWI demonstrated SHA-1 collision with two PDFs
- **SHA-1 deprecation**: Major browsers and CAs stopped accepting SHA-1 certificates after SHAttered
- **Git**: Uses SHA-1 for object hashing; migrating to SHA-256

## Tools Used

- [sha1collider](https://github.com/nneonneo/sha1collider) - SHA-1 PDF collision generator
- [FastColl](https://github.com/brimstone/fastcoll) - MD5 identical-prefix collision generator
- [HashClash](https://github.com/cr-marcstevens/hashclash) - Full MD5/SHA-1 cryptanalytic toolbox

## Recommendation

**Never use MD5 or SHA-1 for security purposes.** Use SHA-256 or SHA-3 for:
- File integrity verification
- Digital signatures
- Certificate fingerprints
- Content addressing

## License

MIT - Educational and research purposes.

## Credits

- Marc Stevens et al. - [SHAttered](https://shattered.io/) SHA-1 collision research
- Marc Stevens - [FastColl](https://www.win.tue.nl/hashclash/) MD5 collision tool
- [Innora AI](https://innora.ai) Security Research Lab - This demonstration
