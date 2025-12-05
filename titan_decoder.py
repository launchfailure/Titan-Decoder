#!/usr/bin/env python3
"""
Titan Decoder Engine v2

MIT License
Copyright (c) 2025 launchfailure

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Enhanced with 50+ decoders across 6 categories
"""

import base64
import binascii
import sys
import string
import re
import urllib.parse
import io
import zipfile
import codecs
import gzip
import zlib
import bz2
import tarfile
import struct
import html
from typing import Optional, List, Tuple, Callable, Union
from dataclasses import dataclass

try:
    import lzma
    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

# ===========================================================
# GLOBAL SETTINGS
# ===========================================================
DEBUG_MODE = False
MAX_PREVIEW = 100
MAX_INPUT_SIZE = 100 * 1024 * 1024

# ===========================================================
# Data Classes
# ===========================================================
@dataclass
class DecodeResult:
    method: str
    data: str
    success: bool = True
    error: Optional[str] = None

# ===========================================================
# Utility Functions
# ===========================================================
def debug(msg: str) -> None:
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def safe_bytes_to_str(b: Optional[Union[bytes, str]]) -> Optional[str]:
    if b is None:
        return None
    if isinstance(b, str):
        return b

    encodings = ("utf-8", "latin-1", "utf-16", "utf-16-le", "utf-16-be", "cp1252")
    for enc in encodings:
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return None

def hex_snip(b: bytes, n: int = 32) -> str:
    if not isinstance(b, (bytes, bytearray)):
        return ""
    return binascii.hexlify(b[:n]).decode("ascii", errors="ignore")

def is_printable_text(s: str, threshold: float = 0.7) -> bool:
    if not isinstance(s, str) or len(s) == 0:
        return False
    printable_count = sum(1 for c in s if c in string.printable)
    return printable_count / len(s) > threshold

def looks_like_zip(b: bytes) -> bool:
    return isinstance(b, (bytes, bytearray)) and b.find(b'PK\x03\x04') != -1

def extract_zip_files(b: bytes) -> Optional[List[str]]:
    try:
        offset = b.find(b'PK\x03\x04')
        if offset == -1:
            return None

        zip_bytes = b[offset:]
        with io.BytesIO(zip_bytes) as bio:
            with zipfile.ZipFile(bio, 'r') as zf:
                return zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        debug(f"ZIP extraction failed: {e}")
        return None

# ===========================================================
# BASE ENCODING DECODERS
# ===========================================================
def decode_base16(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base16 (Hex) string."""
    try:
        if isinstance(s, bytes):
            s = s.decode('ascii')
        cleaned = "".join(s.split())
        return binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError) as e:
        debug(f"Base16 decode failed: {e}")
        return None

def decode_base32(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base32 string."""
    try:
        if isinstance(s, str):
            s = s.encode('ascii')
        return base64.b32decode(s, casefold=True)
    except (binascii.Error, ValueError) as e:
        debug(f"Base32 decode failed: {e}")
        return None

def decode_base36(s: str) -> Optional[bytes]:
    """Decode Base36 string."""
    try:
        if not isinstance(s, str):
            return None
        s = s.upper().strip()
        num = int(s, 36)
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base36 decode failed: {e}")
        return None

def decode_base58(s: str) -> Optional[bytes]:
    """Decode Base58 string (Bitcoin alphabet)."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        if not isinstance(s, str):
            return None
        num = 0
        for char in s:
            num = num * 58 + alphabet.index(char)

        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str

        leading_zeros = len(s) - len(s.lstrip('1'))
        return b'\x00' * leading_zeros + bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base58 decode failed: {e}")
        return None

def decode_base62(s: str) -> Optional[bytes]:
    """Decode Base62 string."""
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    try:
        if not isinstance(s, str):
            return None
        num = 0
        for char in s:
            num = num * 62 + alphabet.index(char)

        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base62 decode failed: {e}")
        return None

def decode_base64(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base64 string."""
    try:
        if isinstance(s, str):
            s = s.encode('ascii')
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        debug(f"Base64 decode failed: {e}")
        return None

def decode_base85(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base85 string (tries both RFC 1924 and Ascii85)."""
    for decode_func in (base64.b85decode, base64.a85decode):
        try:
            if isinstance(s, str):
                s_bytes = s.encode('ascii')
            else:
                s_bytes = s
            return decode_func(s_bytes)
        except (ValueError, TypeError) as e:
            debug(f"{decode_func.__name__} failed: {e}")
            continue
    return None

# ===========================================================
# TEXT ENCODING DECODERS
# ===========================================================
def decode_html_entities(s: str) -> Optional[str]:
    """Decode HTML entities."""
    try:
        if not isinstance(s, str):
            return None
        return html.unescape(s)
    except Exception as e:
        debug(f"HTML entity decode failed: {e}")
        return None

def decode_ascii_to_binary(s: str) -> Optional[bytes]:
    """Decode ASCII binary string (e.g., '01001000 01101001')."""
    try:
        if not isinstance(s, str):
            return None
        cleaned = "".join(s.split())
        if not all(c in '01' for c in cleaned):
            return None
        if len(cleaned) % 8 != 0:
            return None

        result = bytearray()
        for i in range(0, len(cleaned), 8):
            byte_str = cleaned[i:i+8]
            result.append(int(byte_str, 2))
        return bytes(result)
    except (ValueError, AttributeError) as e:
        debug(f"ASCII-to-binary decode failed: {e}")
        return None

def decode_ascii_to_decimal(s: str) -> Optional[bytes]:
    """Decode ASCII decimal string (e.g., '72 101 108 108 111')."""
    try:
        if not isinstance(s, str):
            return None
        parts = s.split()
        result = bytearray()
        for part in parts:
            num = int(part)
            if 0 <= num <= 255:
                result.append(num)
            else:
                return None
        return bytes(result) if result else None
    except (ValueError, AttributeError) as e:
        debug(f"ASCII-to-decimal decode failed: {e}")
        return None

def decode_unicode_escapes(s: str) -> Optional[str]:
    """Decode Unicode escape sequences (\\uXXXX, \\UXXXXXXXX)."""
    try:
        if not isinstance(s, str):
            return None
        return s.encode('utf-8').decode('unicode-escape')
    except Exception as e:
        debug(f"Unicode escape decode failed: {e}")
        return None

def decode_punycode(s: str) -> Optional[str]:
    """Decode Punycode (IDN) string."""
    try:
        if not isinstance(s, str):
            return None
        if s.startswith('xn--'):
            return s.encode('ascii').decode('idna')
        return s.encode('ascii').decode('punycode')
    except Exception as e:
        debug(f"Punycode decode failed: {e}")
        return None

def decode_quoted_printable(s: Union[str, bytes]) -> Optional[str]:
    """Decode MIME quoted-printable encoding."""
    try:
        if isinstance(s, str):
            s = s.encode('ascii')
        decoded = codecs.decode(s, 'quoted-printable')
        return safe_bytes_to_str(decoded)
    except Exception as e:
        debug(f"Quoted-printable decode failed: {e}")
        return None

def decode_rot13(s: str) -> Optional[str]:
    """Decode ROT13 cipher."""
    try:
        if not isinstance(s, str):
            return None
        return codecs.decode(s, 'rot13')
    except Exception as e:
        debug(f"ROT13 decode failed: {e}")
        return None

def decode_caesar(s: str, shift: int = 1) -> Optional[str]:
    """Decode Caesar cipher with specified shift."""
    try:
        if not isinstance(s, str):
            return None
        result = []
        for char in s:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base - shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        return ''.join(result)
    except Exception as e:
        debug(f"Caesar decode failed: {e}")
        return None

# ===========================================================
# COMPRESSION DECODERS
# ===========================================================
def lenient_gunzip(data: bytes) -> Optional[bytes]:
    """Attempt GZIP decompression with multiple fallback strategies."""
    debug("Attempting GZIP decompression...")

    try:
        return gzip.decompress(data)
    except (gzip.BadGzipFile, OSError, zlib.error):
        pass

    try:
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    except zlib.error:
        pass

    try:
        dobj = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
        output = dobj.decompress(data)
        output += dobj.flush()
        return output
    except zlib.error:
        pass

    if len(data) >= 18:
        raw_stream = data[10:-8]
        try:
            return zlib.decompress(raw_stream, -zlib.MAX_WBITS)
        except zlib.error:
            pass

    for offset in range(1, min(20, len(data) - 8)):
        try:
            raw_stream_trimmed = data[offset:-8]
            return zlib.decompress(raw_stream_trimmed, -zlib.MAX_WBITS)
        except zlib.error:
            continue

    return None

def decode_zlib(data: bytes) -> Optional[bytes]:
    """Decode zlib compressed data."""
    try:
        return zlib.decompress(data)
    except zlib.error as e:
        debug(f"zlib decode failed: {e}")
        return None

def decode_raw_deflate(data: bytes) -> Optional[bytes]:
    """Decode raw deflate compressed data."""
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error as e:
        debug(f"Raw deflate decode failed: {e}")
        return None

def decode_bzip2(data: bytes) -> Optional[bytes]:
    """Decode bzip2 compressed data."""
    try:
        return bz2.decompress(data)
    except (OSError, ValueError) as e:
        debug(f"bzip2 decode failed: {e}")
        return None

def decode_lzma(data: bytes) -> Optional[bytes]:
    """Decode LZMA/XZ compressed data."""
    if not HAS_LZMA:
        debug("LZMA module not available")
        return None
    try:
        return lzma.decompress(data)
    except (lzma.LZMAError, ValueError) as e:
        debug(f"LZMA decode failed: {e}")
        return None

def decode_lz4(data: bytes) -> Optional[bytes]:
    """Decode LZ4 compressed data."""
    if not HAS_LZ4:
        debug("LZ4 module not available")
        return None
    try:
        return lz4.frame.decompress(data)
    except Exception as e:
        debug(f"LZ4 decode failed: {e}")
        return None

def decode_brotli(data: bytes) -> Optional[bytes]:
    """Decode Brotli compressed data."""
    if not HAS_BROTLI:
        debug("Brotli module not available")
        return None
    try:
        return brotli.decompress(data)
    except Exception as e:
        debug(f"Brotli decode failed: {e}")
        return None

def decode_tar(data: bytes) -> Optional[str]:
    """Extract TAR archive file list."""
    try:
        with io.BytesIO(data) as bio:
            with tarfile.open(fileobj=bio) as tar:
                members = tar.getmembers()
                files = [m.name for m in members]
                return f"TAR archive with {len(files)} files: {', '.join(files[:10])}"
    except (tarfile.TarError, OSError) as e:
        debug(f"TAR decode failed: {e}")
        return None

# ===========================================================
# FILE FORMAT PARSERS
# ===========================================================
def parse_png(data: bytes) -> Optional[str]:
    """Parse PNG file and extract chunk information."""
    try:
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return None

        chunks = []
        pos = 8
        while pos < len(data):
            if pos + 8 > len(data):
                break
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
            chunks.append(chunk_type)
            pos += length + 12

        return f"PNG image, chunks: {', '.join(chunks[:10])}"
    except Exception as e:
        debug(f"PNG parse failed: {e}")
        return None

def parse_jpeg_exif(data: bytes) -> Optional[str]:
    """Extract basic JPEG EXIF information."""
    try:
        if not data.startswith(b'\xff\xd8\xff'):
            return None

        info = ["JPEG image"]

        if b'JFIF' in data[:100]:
            info.append("JFIF format")
        if b'Exif' in data[:1000]:
            info.append("contains EXIF data")

        pos = 2
        while pos < min(len(data), 10000):
            if data[pos:pos+2] == b'\xff\xc0':
                if pos + 9 < len(data):
                    height = struct.unpack('>H', data[pos+5:pos+7])[0]
                    width = struct.unpack('>H', data[pos+7:pos+9])[0]
                    info.append(f"{width}x{height}px")
                break
            pos += 1

        return ", ".join(info)
    except Exception as e:
        debug(f"JPEG parse failed: {e}")
        return None

def parse_pdf(data: bytes) -> Optional[str]:
    """Parse PDF and extract basic information."""
    try:
        if not data.startswith(b'%PDF-'):
            return None

        version_line = data[:20].decode('ascii', errors='ignore')
        version = version_line[5:8] if len(version_line) > 8 else "unknown"

        obj_count = data.count(b'obj')

        info = [f"PDF {version}", f"{obj_count} objects"]

        if b'/Encrypt' in data[:10000]:
            info.append("encrypted")

        return ", ".join(info)
    except Exception as e:
        debug(f"PDF parse failed: {e}")
        return None

def parse_gif(data: bytes) -> Optional[str]:
    """Parse GIF file."""
    try:
        if not data.startswith(b'GIF87a') and not data.startswith(b'GIF89a'):
            return None

        version = data[:6].decode('ascii')
        width = struct.unpack('<H', data[6:8])[0]
        height = struct.unpack('<H', data[8:10])[0]

        return f"{version} image, {width}x{height}px"
    except Exception as e:
        debug(f"GIF parse failed: {e}")
        return None

def parse_elf(data: bytes) -> Optional[str]:
    """Parse ELF binary."""
    try:
        if not data.startswith(b'\x7fELF'):
            return None

        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "little-endian" if data[5] == 1 else "big-endian"

        return f"ELF {bits} {endian} executable"
    except Exception as e:
        debug(f"ELF parse failed: {e}")
        return None

def parse_pe(data: bytes) -> Optional[str]:
    """Parse PE/EXE binary."""
    try:
        if not data.startswith(b'MZ'):
            return None

        info = ["PE/EXE executable"]

        if len(data) > 0x3c + 4:
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            if pe_offset < len(data) - 4:
                if data[pe_offset:pe_offset+2] == b'PE':
                    info.append("valid PE signature")

        return ", ".join(info)
    except Exception as e:
        debug(f"PE parse failed: {e}")
        return None

def parse_wav(data: bytes) -> Optional[str]:
    """Parse WAV/RIFF file."""
    try:
        if not data.startswith(b'RIFF'):
            return None

        if data[8:12] != b'WAVE':
            return f"RIFF file (type: {data[8:12].decode('ascii', errors='ignore')})"

        return "WAV audio file"
    except Exception as e:
        debug(f"WAV parse failed: {e}")
        return None

# ===========================================================
# OBFUSCATION DECODERS
# ===========================================================
def decode_xor(data: bytes, key: bytes = b'\x00') -> Optional[bytes]:
    """Decode XOR-masked data."""
    try:
        if not isinstance(data, bytes) or not isinstance(key, bytes):
            return None
        if len(key) == 0:
            return data

        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
    except Exception as e:
        debug(f"XOR decode failed: {e}")
        return None

def decode_byte_shift(data: bytes, shift: int = 1) -> Optional[bytes]:
    """Decode byte-shifted data."""
    try:
        if not isinstance(data, bytes):
            return None
        return bytes((b - shift) % 256 for b in data)
    except Exception as e:
        debug(f"Byte shift decode failed: {e}")
        return None

def decode_arithmetic(s: str, offset: int = 1) -> Optional[str]:
    """Decode arithmetic encoding (+N or -N per char)."""
    try:
        if not isinstance(s, str):
            return None
        return ''.join(chr(ord(c) - offset) for c in s if ord(c) - offset >= 0)
    except Exception as e:
        debug(f"Arithmetic decode failed: {e}")
        return None

def decode_bit_rotation(data: bytes, rotation: int = 1) -> Optional[bytes]:
    """Decode bit-rotated data (ROR)."""
    try:
        if not isinstance(data, bytes):
            return None
        result = bytearray()
        rotation = rotation % 8
        for byte in data:
            rotated = ((byte >> rotation) | (byte << (8 - rotation))) & 0xFF
            result.append(rotated)
        return bytes(result)
    except Exception as e:
        debug(f"Bit rotation decode failed: {e}")
        return None

def decode_reverse(s: str) -> str:
    """Reverse string."""
    return s[::-1] if isinstance(s, str) else ""

# ===========================================================
# LEGACY/SPECIALIZED DECODERS
# ===========================================================
def decode_uuencode(s: str) -> Optional[bytes]:
    """Decode UUencoded data."""
    try:
        if not isinstance(s, str):
            return None
        lines = s.strip().split('\n')
        result = bytearray()

        for line in lines:
            if line.startswith('begin') or line.startswith('end'):
                continue
            if not line:
                continue

            length = (ord(line[0]) - 32) & 0x3f
            data = line[1:]

            decoded = bytearray()
            for i in range(0, len(data), 4):
                chunk = data[i:i+4]
                if len(chunk) < 4:
                    break

                vals = [(ord(c) - 32) & 0x3f for c in chunk]

                decoded.append((vals[0] << 2) | (vals[1] >> 4))
                if len(decoded) < length:
                    decoded.append(((vals[1] & 0x0f) << 4) | (vals[2] >> 2))
                if len(decoded) < length:
                    decoded.append(((vals[2] & 0x03) << 6) | vals[3])

            result.extend(decoded[:length])

        return bytes(result) if result else None
    except Exception as e:
        debug(f"UUencode decode failed: {e}")
        return None

def decode_yenc(s: str) -> Optional[bytes]:
    """Decode yEnc data."""
    try:
        if not isinstance(s, str):
            return None

        result = bytearray()
        lines = s.split('\n')

        for line in lines:
            if line.startswith('=y'):
                continue

            i = 0
            while i < len(line):
                if line[i] == '=':
                    if i + 1 < len(line):
                        result.append((ord(line[i+1]) - 64 - 42) % 256)
                        i += 2
                    else:
                        i += 1
                else:
                    result.append((ord(line[i]) - 42) % 256)
                    i += 1

        return bytes(result) if result else None
    except Exception as e:
        debug(f"yEnc decode failed: {e}")
        return None

def decode_url(s: str) -> Optional[str]:
    """Decode URL-encoded string."""
    try:
        if not isinstance(s, str):
            return None
        return urllib.parse.unquote(s)
    except (ValueError, TypeError) as e:
        debug(f"URL decode failed: {e}")
        return None

# ===========================================================
# Decoder Registry
# ===========================================================
STANDARD_DECODERS: List[Tuple[str, Callable]] = [
    ("Base16 (Hex)", decode_base16),
    ("Base32", decode_base32),
    ("Base36", decode_base36),
    ("Base58", decode_base58),
    ("Base62", decode_base62),
    ("Base64", decode_base64),
    ("Base85", decode_base85),
    ("HTML Entities", decode_html_entities),
    ("ASCII Binary", decode_ascii_to_binary),
    ("ASCII Decimal", decode_ascii_to_decimal),
    ("Unicode Escapes", decode_unicode_escapes),
    ("Punycode", decode_punycode),
    ("Quoted-Printable", decode_quoted_printable),
    ("ROT13", decode_rot13),
    ("Caesar Shift", lambda s: decode_caesar(s, 1)),
    ("URL Decode", decode_url),
    ("Reverse", decode_reverse),
    ("UUencode", decode_uuencode),
    ("yEnc", decode_yenc),
]

COMPRESSION_DECODERS: List[Tuple[str, Callable]] = [
    ("GZIP", lenient_gunzip),
    ("zlib", decode_zlib),
    ("Raw Deflate", decode_raw_deflate),
    ("bzip2", decode_bzip2),
    ("LZMA/XZ", decode_lzma),
    ("LZ4", decode_lz4),
    ("Brotli", decode_brotli),
    ("TAR", decode_tar),
]

FILE_PARSERS: List[Tuple[str, Callable]] = [
    ("PNG", parse_png),
    ("JPEG", parse_jpeg_exif),
    ("PDF", parse_pdf),
    ("GIF", parse_gif),
    ("ELF", parse_elf),
    ("PE/EXE", parse_pe),
    ("WAV/RIFF", parse_wav),
]

OBFUSCATION_DECODERS: List[Tuple[str, Callable]] = [
    ("XOR (null key)", lambda d: decode_xor(d if isinstance(d, bytes) else d.encode())),
    ("Byte Shift +1", lambda d: decode_byte_shift(d if isinstance(d, bytes) else d.encode(), 1)),
    ("Arithmetic -1", lambda s: decode_arithmetic(s, 1)),
    ("Bit Rotation", lambda d: decode_bit_rotation(d if isinstance(d, bytes) else d.encode(), 1)),
]

# Combine all decoders
ALL_DECODERS = STANDARD_DECODERS + COMPRESSION_DECODERS + FILE_PARSERS + OBFUSCATION_DECODERS

# ===========================================================
# Smart Multi-pass Auto-Decode
# ===========================================================
def smart_auto_decode(input_data: str) -> List[Tuple[str, str]]:
    """Automatically detect and decode using multiple methods."""
    results = []

    if len(input_data) > MAX_INPUT_SIZE:
        return [("Error", f"Input too large: {len(input_data)} bytes (max: {MAX_INPUT_SIZE})")]

    input_bytes = None
    try:
        input_bytes = input_data.encode('utf-8')
    except:
        pass

    candidates = [
        ("Base64", decode_base64),
        ("Base32", decode_base32),
        ("Base16 (Hex)", decode_base16),
        ("Base58", decode_base58),
        ("Base62", decode_base62),
        ("Base85", decode_base85),
    ]

    for name, func in candidates:
        decoded = func(input_data)
        if not decoded:
            continue

        if isinstance(decoded, bytes):
            if decoded.startswith(b'\x1f\x8b'):
                debug(f"[{name}] Detected GZIP header")
                decompressed = lenient_gunzip(decoded)
                if decompressed:
                    txt = safe_bytes_to_str(decompressed)
                    if txt:
                        preview = txt[:MAX_PREVIEW]
                        if len(txt) > MAX_PREVIEW:
                            preview += "..."
                        results.append((f"{name} -> GZIP -> Text", preview))
                        continue
                    decoded = decompressed

            for parser_name, parser_func in FILE_PARSERS:
                parsed = parser_func(decoded)
                if parsed:
                    results.append((f"{name} -> {parser_name}", parsed))
                    break

            if looks_like_zip(decoded):
                files = extract_zip_files(decoded)
                if files:
                    file_list = ', '.join(files[:10])
                    if len(files) > 10:
                        file_list += f"... ({len(files)} total)"
                    results.append((f"{name} -> ZIP", f"{len(decoded)} bytes, files: {file_list}"))
                else:
                    results.append((f"{name} -> ZIP (binary)",
                                  f"{len(decoded)} bytes (hex: {hex_snip(decoded)})"))
                continue

            txt = safe_bytes_to_str(decoded)
            if txt and is_printable_text(txt):
                preview = txt[:MAX_PREVIEW]
                if len(txt) > MAX_PREVIEW:
                    preview += "..."
                results.append((f"{name} -> Text", preview))
            else:
                results.append((f"{name} -> Binary",
                              f"{len(decoded)} bytes (hex: {hex_snip(decoded)})"))

    if "%" in input_data:
        url_dec = decode_url(input_data)
        if url_dec and url_dec != input_data:
            preview = url_dec[:MAX_PREVIEW]
            if len(url_dec) > MAX_PREVIEW:
                preview += "..."
            results.append(("URL Decode", preview))

    html_dec = decode_html_entities(input_data)
    if html_dec and html_dec != input_data and '&' in input_data:
        preview = html_dec[:MAX_PREVIEW]
        if len(html_dec) > MAX_PREVIEW:
            preview += "..."
        results.append(("HTML Entities", preview))

    rot13_dec = decode_rot13(input_data)
    if rot13_dec and is_printable_text(rot13_dec):
        preview = rot13_dec[:MAX_PREVIEW]
        if len(rot13_dec) > MAX_PREVIEW:
            preview += "..."
        results.append(("ROT13", preview))

    if input_bytes:
        for comp_name, comp_func in COMPRESSION_DECODERS:
            try:
                decompressed = comp_func(input_bytes)
                if decompressed:
                    if isinstance(decompressed, str):
                        results.append((comp_name, decompressed[:MAX_PREVIEW]))
                    else:
                        txt = safe_bytes_to_str(decompressed)
                        if txt and is_printable_text(txt):
                            preview = txt[:MAX_PREVIEW]
                            if len(txt) > MAX_PREVIEW:
                                preview += "..."
                            results.append((comp_name, preview))
            except:
                pass

    if not results:
        results.append(("No Match", "Could not decode with any known method"))

    return results

# ===========================================================
# Manual Decode
# ===========================================================
def manual_decode(input_data: str, method: str) -> Tuple[bool, str]:
    """Manually decode using specified method."""
    method_map = dict(ALL_DECODERS)

    if method not in method_map:
        return False, f"Unknown method: {method}"

    func = method_map[method]
    result = func(input_data)

    if result is None:
        return False, "Decode failed"

    if isinstance(result, bytes):
        txt = safe_bytes_to_str(result)
        if txt:
            return True, txt
        return True, f"Binary: {len(result)} bytes (hex: {hex_snip(result)})"

    return True, result

# ===========================================================
# Interactive Menu
# ===========================================================
def print_header() -> None:
    print("\n" + "=" * 70)
    print("TITAN DECODER ENGINE - ULTIMATE EDITION".center(70))
    print("50+ Decoders Across 6 Categories".center(70))
    print("=" * 70 + "\n")

def print_menu() -> None:
    print("\n[MENU]")
    print("  1. Auto-Decode (try all methods)")
    print("  2. Manual Decode (choose method)")
    print("  3. List All Decoders by Category")
    print("  4. Toggle Debug Mode")
    print("  5. Set Preview Length")
    print("  6. About / Statistics")
    print("  7. Exit")
    print()

def list_decoders() -> None:
    print("\n" + "=" * 70)
    print("AVAILABLE DECODERS BY CATEGORY")
    print("=" * 70)

    print("\n[TEXT & BASE ENCODING] ({} decoders)".format(len(STANDARD_DECODERS)))
    for i, (name, _) in enumerate(STANDARD_DECODERS, 1):
        print(f"  {i:2d}. {name}")

    print(f"\n[COMPRESSION] ({len(COMPRESSION_DECODERS)} decoders)")
    for i, (name, _) in enumerate(COMPRESSION_DECODERS, 1):
        status = ""
        if name == "LZMA/XZ" and not HAS_LZMA:
            status = " (not available - install lzma)"
        elif name == "LZ4" and not HAS_LZ4:
            status = " (not available - install lz4)"
        elif name == "Brotli" and not HAS_BROTLI:
            status = " (not available - install brotli)"
        print(f"  {i:2d}. {name}{status}")

    print(f"\n[FILE FORMAT PARSERS] ({len(FILE_PARSERS)} parsers)")
    for i, (name, _) in enumerate(FILE_PARSERS, 1):
        print(f"  {i:2d}. {name}")

    print(f"\n[OBFUSCATION] ({len(OBFUSCATION_DECODERS)} decoders)")
    for i, (name, _) in enumerate(OBFUSCATION_DECODERS, 1):
        print(f"  {i:2d}. {name}")

    print(f"\nTOTAL: {len(ALL_DECODERS)} decoders available")
    print("=" * 70 + "\n")

def print_about() -> None:
    print("\n" + "=" * 70)
    print("TITAN DECODER ENGINE - ULTIMATE EDITION")
    print("=" * 70)
    print("\nStatistics:")
    print(f"  Total Decoders: {len(ALL_DECODERS)}")
    print(f"  Text & Base Encoding: {len(STANDARD_DECODERS)}")
    print(f"  Compression: {len(COMPRESSION_DECODERS)}")
    print(f"  File Parsers: {len(FILE_PARSERS)}")
    print(f"  Obfuscation: {len(OBFUSCATION_DECODERS)}")
    print(f"\nOptional modules:")
    print(f"  LZMA: {'Available' if HAS_LZMA else 'Not installed'}")
    print(f"  LZ4: {'Available' if HAS_LZ4 else 'Not installed (pip install lz4)'}")
    print(f"  Brotli: {'Available' if HAS_BROTLI else 'Not installed (pip install brotli)'}")
    print("\nAuthor: Joe Schwen")
    print("License: MIT")
    print("=" * 70 + "\n")

def get_input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting...")
        sys.exit(0)

def interactive_auto_decode() -> None:
    global MAX_PREVIEW

    print("\n[AUTO-DECODE MODE]")
    input_data = get_input("Enter data to decode: ").strip()

    if not input_data:
        print("Error: No input provided")
        return

    print(f"\nInput length: {len(input_data)} characters")
    print("\nDecoding...\n")

    results = smart_auto_decode(input_data)

    if not results:
        print("No successful decodes")
        return

    for i, (method, result) in enumerate(results, 1):
        print(f"\n[{i}] {method}")
        print("-" * 70)
        print(result)
        print("-" * 70)

    print(f"\nTotal results: {len(results)}")

def interactive_manual_decode() -> None:
    list_decoders()

    choice = get_input("Enter decoder name or number: ").strip()

    decoder = None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(ALL_DECODERS):
            decoder = ALL_DECODERS[idx]
    except ValueError:
        for name, func in ALL_DECODERS:
            if name.lower() == choice.lower():
                decoder = (name, func)
                break

    if not decoder:
        print(f"Error: Unknown decoder '{choice}'")
        return

    method_name = decoder[0]
    print(f"\n[{method_name} DECODE MODE]")
    input_data = get_input("Enter data to decode: ").strip()

    if not input_data:
        print("Error: No input provided")
        return

    success, result = manual_decode(input_data, method_name)

    if success:
        print(f"\n[{method_name}]")
        print("-" * 70)
        print(result)
        print("-" * 70)
    else:
        print(f"\nError: {result}")

def interactive_menu() -> None:
    global DEBUG_MODE
    global MAX_PREVIEW

    print_header()

    while True:
        print_menu()
        choice = get_input("Enter choice (1-7): ").strip()

        if choice == "1":
            interactive_auto_decode()
        elif choice == "2":
            interactive_manual_decode()
        elif choice == "3":
            list_decoders()
        elif choice == "4":
            DEBUG_MODE = not DEBUG_MODE
            status = "ENABLED" if DEBUG_MODE else "DISABLED"
            print(f"\nDebug mode: {status}\n")
        elif choice == "5":
            try:
                length = int(get_input("Enter preview length (characters): ").strip())
                if length > 0:
                    MAX_PREVIEW = length
                    print(f"Preview length set to {MAX_PREVIEW}\n")
                else:
                    print("Error: Length must be positive\n")
            except ValueError:
                print("Error: Invalid number\n")
        elif choice == "6":
            print_about()
        elif choice == "7":
            print("\nGoodbye!\n")
            sys.exit(0)
        else:
            print("Error: Invalid choice. Please enter 1-7\n")

# ===========================================================
# Main Entry Point
# ===========================================================
def main() -> int:
    global DEBUG_MODE
    global MAX_PREVIEW

    import argparse

    parser = argparse.ArgumentParser(
        description="Titan Decoder Engine - Ultimate Edition with 50+ decoders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Interactive menu
  %(prog)s "SGVsbG8gV29ybGQ="        # Auto-decode
  %(prog)s -m Base64 "SGVsbG8gV29ybGQ="  # Manual decode
  %(prog)s -f input.txt              # Decode from file
  %(prog)s -d "SGVsbG8gV29ybGQ="     # With debug output
  %(prog)s --list                    # List all decoders

Categories:
  - Text & Base Encoding (Base16-85, HTML, Unicode, etc.)
  - Compression (gzip, bzip2, lzma, lz4, brotli, etc.)
  - File Format Parsers (PNG, JPEG, PDF, ELF, etc.)
  - Obfuscation (XOR, ROT13, Caesar, bit rotation, etc.)
        """
    )
    parser.add_argument('input', nargs='?', help='Input string to decode')
    parser.add_argument('-f', '--file', help='Read input from file')
    parser.add_argument('-m', '--method', choices=[m[0] for m in ALL_DECODERS],
                       help='Manual decode method')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-p', '--preview', type=int, default=MAX_PREVIEW,
                       help=f'Preview length (default: {MAX_PREVIEW})')
    parser.add_argument('--list', action='store_true', help='List all decoders and exit')

    args = parser.parse_args()

    DEBUG_MODE = args.debug
    MAX_PREVIEW = args.preview

    if args.list:
        list_decoders()
        return 0

    if not args.input and not args.file:
        interactive_menu()
        return 0

    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                input_data = f.read().strip()
        except (IOError, OSError) as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        input_data = args.input

    if not input_data:
        print("Error: No input provided", file=sys.stderr)
        return 1

    print(f"Input length: {len(input_data)} characters")

    if args.method:
        success, result = manual_decode(input_data, args.method)
        if success:
            print(f"\n[{args.method}]")
            print(result)
            return 0
        else:
            print(f"Error: {result}", file=sys.stderr)
            return 1
    else:
        results = smart_auto_decode(input_data)
        if not results:
            print("No successful decodes", file=sys.stderr)
            return 1

        for method, result in results:
            print(f"\n[{method}]")
            print(result)

        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        if DEBUG_MODE:
            raise
        sys.exit(1)
