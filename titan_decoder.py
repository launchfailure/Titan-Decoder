#!/usr/bin/env python3
"""
Titan Decoder Engine v2 (Updated)
Applied fixes:
 - base64 padding tolerance
 - punycode robustness
 - arithmetic decoder preserves characters
 - obfuscation decoders handle bytes/str safely
 - file parsers return bytes (normalized)
 - added 5 new decoders (Base91, Morse, Vigenere, Base92, XOR brute)
 - normalized decoder outputs to bytes
MIT License
Author: Joe Schwen (original) + updates
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

# Optional third-party decoders
try:
    import base91  # type: ignore
    HAS_BASE91 = True
except Exception:
    HAS_BASE91 = False

try:
    import base92  # type: ignore
    HAS_BASE92 = True
except Exception:
    HAS_BASE92 = False

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
    data: bytes
    success: bool = True
    error: Optional[str] = None

# ===========================================================
# Utility Functions
# ===========================================================
def debug(msg: str) -> None:
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def to_bytes_safe(x: Union[str, bytes], encoding: str = "latin-1") -> bytes:
    """Convert str->bytes using latin-1 by default (preserve byte values)."""
    if isinstance(x, bytes):
        return x
    return x.encode(encoding, errors="surrogatepass")

def safe_bytes_to_str(b: Optional[Union[bytes, str]]) -> Optional[str]:
    if b is None:
        return None
    if isinstance(b, str):
        return b
    # try a series of encodings
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

def ensure_text_bytes(b: bytes) -> bytes:
    """If bytes are printable text, return bytes. Else unchanged."""
    s = safe_bytes_to_str(b)
    if s and is_printable_text(s):
        return s.encode('utf-8')
    return b

# ===========================================================
# Decoder return normalization helper
# ===========================================================
def normalize_decoder_return(func: Callable[[Union[str, bytes]], Optional[Union[str, bytes]]]) -> Callable[[Union[str, bytes]], Optional[bytes]]:
    """
    Wrap a decoder that may return str or bytes into one that returns bytes or None.
    If decoding returns a str, we encode to UTF-8 bytes.
    """
    def wrapped(data: Union[str, bytes]) -> Optional[bytes]:
        try:
            res = func(data)
            if res is None:
                return None
            if isinstance(res, bytes):
                return res
            if isinstance(res, str):
                return res.encode('utf-8', errors='replace')
            # unexpected type
            return None
        except Exception as e:
            debug(f"{func.__name__} wrapper caught exception: {e}")
            return None
    return wrapped

# ===========================================================
# BASE ENCODING DECODERS (return bytes)
# ===========================================================
def _fix_b64_padding(s: bytes) -> bytes:
    # remove whitespace then add padding
    s_clean = b"".join(s.split())
    pad_len = (-len(s_clean)) % 4
    if pad_len:
        s_clean += b'=' * pad_len
    return s_clean

def decode_base16(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        b = to_bytes_safe(s, encoding='ascii')
        cleaned = b"".join(b.split())
        return binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError) as e:
        debug(f"Base16 decode failed: {e}")
        return None

def decode_base32(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        b = to_bytes_safe(s, encoding='ascii')
        # base32 requires padding; tolerate missing padding
        b = _fix_b64_padding(b)
        return base64.b32decode(b, casefold=True)
    except (binascii.Error, ValueError) as e:
        debug(f"Base32 decode failed: {e}")
        return None

def decode_base36(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        if not isinstance(s, (str, bytes)):
            return None
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        s_str = s_str.upper().strip()
        num = int(s_str, 36)
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base36 decode failed: {e}")
        return None

def decode_base58(s: Union[str, bytes]) -> Optional[bytes]:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        num = 0
        for char in s_str:
            num = num * 58 + alphabet.index(char)
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        leading_zeros = len(s_str) - len(s_str.lstrip('1'))
        return b'\x00' * leading_zeros + bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base58 decode failed: {e}")
        return None

def decode_base62(s: Union[str, bytes]) -> Optional[bytes]:
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    try:
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        num = 0
        for char in s_str:
            num = num * 62 + alphabet.index(char)
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except (ValueError, AttributeError) as e:
        debug(f"Base62 decode failed: {e}")
        return None

def decode_base64(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base64 with tolerance for missing padding and URL-safe variant."""
    try:
        b = to_bytes_safe(s, encoding='ascii')
    except Exception:
        return None

    # try standard strict first (validate)
    try:
        return base64.b64decode(b, validate=True)
    except Exception:
        pass

    # Try with fixed padding
    try:
        padded = _fix_b64_padding(b)
        return base64.b64decode(padded, validate=False)
    except Exception:
        pass

    # Try URL-safe base64 with padding
    try:
        padded = _fix_b64_padding(b.replace(b'-', b'+').replace(b'_', b'/'))
        return base64.b64decode(padded, validate=False)
    except Exception as e:
        debug(f"Base64 fallback failed: {e}")
        return None

def decode_base85(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode Base85: try b85 then a85."""
    b = to_bytes_safe(s, encoding='ascii')
    for func in (base64.b85decode, base64.a85decode):
        try:
            return func(b)
        except Exception as e:
            debug(f"{func.__name__} failed: {e}")
            continue
    return None

# ===========================================================
# TEXT ENCODING DECODERS (return bytes)
# ===========================================================
def decode_html_entities(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        return html.unescape(s_str).encode('utf-8')
    except Exception as e:
        debug(f"HTML entity decode failed: {e}")
        return None

def decode_ascii_to_binary(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        cleaned = "".join(s_str.split())
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

def decode_ascii_to_decimal(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        parts = s_str.split()
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

def decode_unicode_escapes(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        return s_str.encode('utf-8').decode('unicode-escape').encode('utf-8')
    except Exception as e:
        debug(f"Unicode escape decode failed: {e}")
        return None

def decode_punycode(s: Union[str, bytes]) -> Optional[bytes]:
    """Decode punycode / IDN: return UTF-8 bytes if possible."""
    try:
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        # If it's an IDNA label with xn--, idna decode will work
        if s_str.startswith('xn--'):
            try:
                decoded = s_str.encode('ascii').decode('idna')  # yields str
                return decoded.encode('utf-8')
            except Exception as e:
                debug(f"IDNA decode failed: {e}")
                # fall through to punycode attempt
        # Try punycode decode (rarely used alone)
        try:
            decoded = codecs.decode(s_str, 'punycode')
            return decoded.encode('utf-8')
        except Exception as e:
            debug(f"Punycode decode failed: {e}")
            return None
    except Exception as e:
        debug(f"Punycode outer error: {e}")
        return None

def decode_quoted_printable(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        b = to_bytes_safe(s, encoding='ascii')
        decoded = codecs.decode(b, 'quoted-printable')
        return to_bytes_safe(decoded, encoding='utf-8')
    except Exception as e:
        debug(f"Quoted-printable decode failed: {e}")
        return None

def decode_rot13(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        return codecs.decode(s_str, 'rot13').encode('utf-8')
    except Exception as e:
        debug(f"ROT13 decode failed: {e}")
        return None

def decode_caesar(s: Union[str, bytes], shift: int = 1) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        result = []
        for char in s_str:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base - shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        return ''.join(result).encode('utf-8')
    except Exception as e:
        debug(f"Caesar decode failed: {e}")
        return None

# ===========================================================
# COMPRESSION DECODERS (return bytes)
# ===========================================================
def lenient_gunzip(data: bytes) -> Optional[bytes]:
    debug("Attempting GZIP decompression...")
    try:
        return gzip.decompress(data)
    except (gzip.BadGzipFile, OSError, zlib.error):
        pass
    # Try zlib with gzip wrapper
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
    # Try raw inflate windows
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error:
        pass
    # Try trimming potential header/footer
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
    try:
        return zlib.decompress(data)
    except zlib.error as e:
        debug(f"zlib decode failed: {e}")
        return None

def decode_raw_deflate(data: bytes) -> Optional[bytes]:
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error as e:
        debug(f"Raw deflate decode failed: {e}")
        return None

def decode_bzip2(data: bytes) -> Optional[bytes]:
    try:
        return bz2.decompress(data)
    except (OSError, ValueError) as e:
        debug(f"bzip2 decode failed: {e}")
        return None

def decode_lzma(data: bytes) -> Optional[bytes]:
    if not HAS_LZMA:
        debug("LZMA module not available")
        return None
    try:
        return lzma.decompress(data)
    except (lzma.LZMAError, ValueError) as e:
        debug(f"LZMA decode failed: {e}")
        return None

def decode_lz4(data: bytes) -> Optional[bytes]:
    if not HAS_LZ4:
        debug("LZ4 module not available")
        return None
    try:
        return lz4.frame.decompress(data)
    except Exception as e:
        debug(f"LZ4 decode failed: {e}")
        return None

def decode_brotli(data: bytes) -> Optional[bytes]:
    if not HAS_BROTLI:
        debug("Brotli module not available")
        return None
    try:
        return brotli.decompress(data)
    except Exception as e:
        debug(f"Brotli decode failed: {e}")
        return None

def decode_tar(data: bytes) -> Optional[bytes]:
    try:
        with io.BytesIO(data) as bio:
            with tarfile.open(fileobj=bio) as tar:
                members = tar.getmembers()
                files = [m.name for m in members]
                desc = f"TAR archive with {len(files)} files: {', '.join(files[:10])}"
                return desc.encode('utf-8')
    except (tarfile.TarError, OSError) as e:
        debug(f"TAR decode failed: {e}")
        return None

# ===========================================================
# FILE FORMAT PARSERS (return bytes descriptions)
# ===========================================================
def parse_png(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return None
        chunks = []
        pos = 8
        while pos + 8 <= len(data):
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
            chunks.append(chunk_type)
            pos += length + 12
        return f"PNG image, chunks: {', '.join(chunks[:10])}".encode('utf-8')
    except Exception as e:
        debug(f"PNG parse failed: {e}")
        return None

def parse_jpeg_exif(data: bytes) -> Optional[bytes]:
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
        return ", ".join(info).encode('utf-8')
    except Exception as e:
        debug(f"JPEG parse failed: {e}")
        return None

def parse_pdf(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'%PDF-'):
            return None
        version_line = data[:20].decode('ascii', errors='ignore')
        version = version_line[5:8] if len(version_line) > 8 else "unknown"
        obj_count = data.count(b'obj')
        info = [f"PDF {version}", f"{obj_count} objects"]
        if b'/Encrypt' in data[:10000]:
            info.append("encrypted")
        return ", ".join(info).encode('utf-8')
    except Exception as e:
        debug(f"PDF parse failed: {e}")
        return None

def parse_gif(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'GIF87a') and not data.startswith(b'GIF89a'):
            return None
        version = data[:6].decode('ascii', errors='ignore')
        width = struct.unpack('<H', data[6:8])[0]
        height = struct.unpack('<H', data[8:10])[0]
        return f"{version} image, {width}x{height}px".encode('utf-8')
    except Exception as e:
        debug(f"GIF parse failed: {e}")
        return None

def parse_elf(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'\x7fELF'):
            return None
        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "little-endian" if data[5] == 1 else "big-endian"
        return f"ELF {bits} {endian} executable".encode('utf-8')
    except Exception as e:
        debug(f"ELF parse failed: {e}")
        return None

def parse_pe(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'MZ'):
            return None
        info = ["PE/EXE executable"]
        if len(data) > 0x3c + 4:
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            if pe_offset < len(data) - 4:
                if data[pe_offset:pe_offset+2] == b'PE':
                    info.append("valid PE signature")
        return ", ".join(info).encode('utf-8')
    except Exception as e:
        debug(f"PE parse failed: {e}")
        return None

def parse_wav(data: bytes) -> Optional[bytes]:
    try:
        if not data.startswith(b'RIFF'):
            return None
        if data[8:12] != b'WAVE':
            return f"RIFF file (type: {data[8:12].decode('ascii', errors='ignore')})".encode('utf-8')
        return b"WAV audio file"
    except Exception as e:
        debug(f"WAV parse failed: {e}")
        return None

# ===========================================================
# OBFUSCATION DECODERS (return bytes)
# ===========================================================
def decode_xor(data: Union[str, bytes], key: Union[str, bytes] = b'\x00') -> Optional[bytes]:
    try:
        db = to_bytes_safe(data)
        kb = to_bytes_safe(key)
        if len(kb) == 0:
            return db
        return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(db))
    except Exception as e:
        debug(f"XOR decode failed: {e}")
        return None

def decode_byte_shift(data: Union[str, bytes], shift: int = 1) -> Optional[bytes]:
    try:
        db = to_bytes_safe(data)
        return bytes((b - shift) % 256 for b in db)
    except Exception as e:
        debug(f"Byte shift decode failed: {e}")
        return None

def decode_arithmetic(s: Union[str, bytes], offset: int = 1) -> Optional[bytes]:
    """Subtract offset from each character codepoint; preserve characters when underflow would occur."""
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        result_chars = []
        for c in s_str:
            new_ord = ord(c) - offset
            if new_ord < 0:
                # preserve original to avoid dropping
                result_chars.append(c)
            else:
                result_chars.append(chr(new_ord))
        return ''.join(result_chars).encode('utf-8')
    except Exception as e:
        debug(f"Arithmetic decode failed: {e}")
        return None

def decode_bit_rotation(data: Union[str, bytes], rotation: int = 1) -> Optional[bytes]:
    try:
        db = to_bytes_safe(data)
        rotation = rotation % 8
        result = bytearray()
        for byte in db:
            rotated = ((byte >> rotation) | (byte << (8 - rotation))) & 0xFF
            result.append(rotated)
        return bytes(result)
    except Exception as e:
        debug(f"Bit rotation decode failed: {e}")
        return None

def decode_reverse(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        if isinstance(s, bytes):
            return s[::-1]
        return s[::-1].encode('utf-8')
    except Exception as e:
        debug(f"Reverse decode failed: {e}")
        return None

# ===========================================================
# LEGACY/SPECIALIZED DECODERS (return bytes)
# ===========================================================
def decode_uuencode(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        lines = s_str.strip().split('\n')
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

def decode_yenc(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        result = bytearray()
        lines = s_str.split('\n')
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

def decode_url(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        return urllib.parse.unquote(s_str).encode('utf-8')
    except (ValueError, TypeError) as e:
        debug(f"URL decode failed: {e}")
        return None

# ===========================================================
# NEW DECODERS ADDED
# All return bytes or None
# ===========================================================
def decode_base91_fallback(s: Union[str, bytes]) -> Optional[bytes]:
    """Try third-party base91 if available."""
    try:
        if not HAS_BASE91:
            debug("base91 not installed")
            return None
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        return base91.decode(s_str)
    except Exception as e:
        debug(f"Base91 decode failed: {e}")
        return None

MORSE_TABLE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
    '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
    '---..':'8','----.':'9','/':' '
}

def decode_morse(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8') if isinstance(s, bytes) else s
        # separators: space between letters, slash between words or ' / '
        words = s_str.strip().split(' / ')
        decoded_words = []
        for word in words:
            letters = word.strip().split()
            decoded_letters = []
            for letter in letters:
                decoded_letters.append(MORSE_TABLE.get(letter, '?'))
            decoded_words.append(''.join(decoded_letters))
        return ' '.join(decoded_words).encode('utf-8')
    except Exception as e:
        debug(f"Morse decode failed: {e}")
        return None

def decode_vigenere(s: Union[str, bytes], key: str = "KEY") -> Optional[bytes]:
    try:
        s_str = s.decode('utf-8', errors='surrogatepass') if isinstance(s, bytes) else s
        result = []
        key = key or "KEY"
        key_i = 0
        for ch in s_str:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                keych = key[key_i % len(key)]
                shift = ord(keych.lower()) - ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                key_i += 1
            else:
                result.append(ch)
        return ''.join(result).encode('utf-8')
    except Exception as e:
        debug(f"Vigenere decode failed: {e}")
        return None

def decode_base92_fallback(s: Union[str, bytes]) -> Optional[bytes]:
    try:
        if not HAS_BASE92:
            debug("base92 not installed")
            return None
        s_str = s.decode('ascii') if isinstance(s, bytes) else s
        return base92.decode(s_str)
    except Exception as e:
        debug(f"Base92 decode failed: {e}")
        return None

def decode_xor_bruteforce_singlebyte(s: Union[str, bytes]) -> Optional[bytes]:
    """
    Try all single-byte XOR keys and return a concatenated preview of plausible results.
    This returns UTF-8 bytes containing candidate keys and text previews.
    """
    try:
        db = to_bytes_safe(s)
        candidates = []
        for k in range(256):
            decoded = bytes(b ^ k for b in db)
            # heuristics: check if first up-to-40 bytes are mostly printable ASCII
            preview = decoded[:40]
            try:
                text = preview.decode('utf-8')
                printable_ratio = sum(1 for c in text if c in string.printable) / max(1, len(text))
                if printable_ratio > 0.8:
                    candidates.append((k, decoded))
            except Exception:
                continue
        if not candidates:
            return None
        # produce a readable summary
        lines = []
        for k, dec in candidates[:10]:
            snippet = safe_bytes_to_str(dec[:200]) or hex_snip(dec, 32)
            lines.append(f"key=0x{k:02x}: {snippet}")
        return "\n".join(lines).encode('utf-8')
    except Exception as e:
        debug(f"XOR brute force failed: {e}")
        return None

# ===========================================================
# Decoder Registry (wrapped to ensure bytes output)
# ===========================================================
STANDARD_DECODERS: List[Tuple[str, Callable[[Union[str, bytes]], Optional[bytes]]]] = [
    ("Base16 (Hex)", normalize_decoder_return(decode_base16)),
    ("Base32", normalize_decoder_return(decode_base32)),
    ("Base36", normalize_decoder_return(decode_base36)),
    ("Base58", normalize_decoder_return(decode_base58)),
    ("Base62", normalize_decoder_return(decode_base62)),
    ("Base64", normalize_decoder_return(decode_base64)),
    ("Base85", normalize_decoder_return(decode_base85)),
    ("HTML Entities", normalize_decoder_return(decode_html_entities)),
    ("ASCII Binary", normalize_decoder_return(decode_ascii_to_binary)),
    ("ASCII Decimal", normalize_decoder_return(decode_ascii_to_decimal)),
    ("Unicode Escapes", normalize_decoder_return(decode_unicode_escapes)),
    ("Punycode", normalize_decoder_return(decode_punycode)),
    ("Quoted-Printable", normalize_decoder_return(decode_quoted_printable)),
    ("ROT13", normalize_decoder_return(decode_rot13)),
    ("Caesar Shift", normalize_decoder_return(lambda s: decode_caesar(s, 1))),
    ("URL Decode", normalize_decoder_return(decode_url)),
    ("Reverse", normalize_decoder_return(decode_reverse)),
    ("UUencode", normalize_decoder_return(decode_uuencode)),
    ("yEnc", normalize_decoder_return(decode_yenc)),
    # New additions
    ("Base91", normalize_decoder_return(decode_base91_fallback)),
    ("Morse Code", normalize_decoder_return(decode_morse)),
    ("Vigenere (key=KEY)", normalize_decoder_return(lambda s: decode_vigenere(s, "KEY"))),
    ("Base92", normalize_decoder_return(decode_base92_fallback)),
]

COMPRESSION_DECODERS: List[Tuple[str, Callable[[bytes], Optional[bytes]]]] = [
    ("GZIP", lenient_gunzip),
    ("zlib", decode_zlib),
    ("Raw Deflate", decode_raw_deflate),
    ("bzip2", decode_bzip2),
    ("LZMA/XZ", decode_lzma),
    ("LZ4", decode_lz4),
    ("Brotli", decode_brotli),
    ("TAR", decode_tar),
]

FILE_PARSERS: List[Tuple[str, Callable[[bytes], Optional[bytes]]]] = [
    ("PNG", parse_png),
    ("JPEG", parse_jpeg_exif),
    ("PDF", parse_pdf),
    ("GIF", parse_gif),
    ("ELF", parse_elf),
    ("PE/EXE", parse_pe),
    ("WAV/RIFF", parse_wav),
]

OBFUSCATION_DECODERS: List[Tuple[str, Callable[[Union[str, bytes]], Optional[bytes]]]] = [
    ("XOR (null key)", normalize_decoder_return(lambda d: decode_xor(d, b'\x00'))),
    ("Byte Shift +1", normalize_decoder_return(lambda d: decode_byte_shift(d, 1))),
    ("Arithmetic -1", normalize_decoder_return(lambda s: decode_arithmetic(s, 1))),
    ("Bit Rotation", normalize_decoder_return(lambda d: decode_bit_rotation(d, 1))),
    ("XOR Single-byte Bruteforce", normalize_decoder_return(decode_xor_bruteforce_singlebyte)),
]

# Combine all decoders for manual selection
ALL_DECODERS = STANDARD_DECODERS + [(n, c) for n, c in COMPRESSION_DECODERS] + FILE_PARSERS + OBFUSCATION_DECODERS

# ===========================================================
# Smart Multi-pass Auto-Decode (uses bytes responses)
# ===========================================================
def smart_auto_decode(input_data: str) -> List[Tuple[str, str]]:
    """
    Automatically detect and decode using multiple methods.
    Returns list of (method, preview string).
    """
    results: List[Tuple[str, str]] = []

    if len(input_data) > MAX_INPUT_SIZE:
        return [("Error", f"Input too large: {len(input_data)} bytes (max: {MAX_INPUT_SIZE})")]

    input_bytes = None
    try:
        # try to keep original textual bytes (latin-1 keeps raw bytes)
        input_bytes = to_bytes_safe(input_data)
    except Exception:
        input_bytes = None

    # Candidate base encodings to try first
    candidates = [
        ("Base64", lambda s: normalize_decoder_return(decode_base64)(s)),
        ("Base32", lambda s: normalize_decoder_return(decode_base32)(s)),
        ("Base16 (Hex)", lambda s: normalize_decoder_return(decode_base16)(s)),
        ("Base58", lambda s: normalize_decoder_return(decode_base58)(s)),
        ("Base62", lambda s: normalize_decoder_return(decode_base62)(s)),
        ("Base85", lambda s: normalize_decoder_return(decode_base85)(s)),
    ]

    for name, func in candidates:
        decoded = func(input_data)
        if not decoded:
            continue

        # If decoded bytes look like gzip, try decompressing
        if decoded.startswith(b'\x1f\x8b') or decoded.startswith(b'\x78\x9c'):
            debug(f"[{name}] Detected compressed header; trying GZIP/zlib")
            decompressed = lenient_gunzip(decoded) or decode_zlib(decoded) or decode_raw_deflate(decoded)
            if decompressed:
                txt = safe_bytes_to_str(decompressed)
                if txt:
                    preview = txt[:MAX_PREVIEW] + ("..." if len(txt) > MAX_PREVIEW else "")
                    results.append((f"{name} -> Decompressed -> Text", preview))
                    continue
                decoded = decompressed

        # Try file parsers
        for parser_name, parser_func in FILE_PARSERS:
            parsed = parser_func(decoded)
            if parsed:
                parsed_str = safe_bytes_to_str(parsed) or hex_snip(parsed, 64)
                results.append((f"{name} -> {parser_name}", parsed_str))
                break
        else:
            # Not a known file parser; check for zip inside
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
                preview = txt[:MAX_PREVIEW] + ("..." if len(txt) > MAX_PREVIEW else "")
                results.append((f"{name} -> Text", preview))
            else:
                results.append((f"{name} -> Binary",
                              f"{len(decoded)} bytes (hex: {hex_snip(decoded)})"))

    # URL decode heuristic
    if "%" in input_data:
        url_dec = decode_url(input_data.encode('utf-8') if isinstance(input_data, str) else input_data)
        if url_dec:
            url_str = safe_bytes_to_str(url_dec) or hex_snip(url_dec)
            if url_str != input_data:
                preview = url_str[:MAX_PREVIEW] + ("..." if len(url_str) > MAX_PREVIEW else "")
                results.append(("URL Decode", preview))

    # HTML entities heuristic
    html_dec = decode_html_entities(input_data)
    if html_dec:
        html_str = safe_bytes_to_str(html_dec) or ""
        if html_str != input_data and '&' in input_data:
            preview = html_str[:MAX_PREVIEW] + ("..." if len(html_str) > MAX_PREVIEW else "")
            results.append(("HTML Entities", preview))

    # ROT13 heuristic
    rot13_dec = decode_rot13(input_data)
    if rot13_dec:
        rot13_str = safe_bytes_to_str(rot13_dec) or ""
        if is_printable_text(rot13_str):
            preview = rot13_str[:MAX_PREVIEW] + ("..." if len(rot13_str) > MAX_PREVIEW else "")
            results.append(("ROT13", preview))

    # Try compression decoders directly on input bytes
    if input_bytes:
        for comp_name, comp_func in COMPRESSION_DECODERS:
            try:
                decompressed = comp_func(input_bytes)
                if decompressed:
                    txt = safe_bytes_to_str(decompressed)
                    if txt and is_printable_text(txt):
                        preview = txt[:MAX_PREVIEW] + ("..." if len(txt) > MAX_PREVIEW else "")
                        results.append((comp_name, preview))
                    else:
                        results.append((comp_name, f"{len(decompressed)} bytes (hex: {hex_snip(decompressed)})"))
            except Exception:
                pass

    if not results:
        results.append(("No Match", "Could not decode with any known method"))

    return results

# ===========================================================
# Manual Decode (uses normalized decoders)
# ===========================================================
def manual_decode(input_data: Union[str, bytes], method: str) -> Tuple[bool, str]:
    method_map = {name: func for (name, func) in ALL_DECODERS}

    if method not in method_map:
        return False, f"Unknown method: {method}"

    func = method_map[method]
    try:
        raw_result = func(input_data)
    except Exception as e:
        debug(f"manual_decode: decoder raised {e}")
        return False, "Decode failed (exception)"

    if raw_result is None:
        return False, "Decode failed"

    # raw_result is bytes; try to present printable text else summary
    txt = safe_bytes_to_str(raw_result)
    if txt and is_printable_text(txt):
        return True, txt
    return True, f"Binary: {len(raw_result)} bytes (hex: {hex_snip(raw_result)})"

# ===========================================================
# Interactive Menu (unchanged interface, improved internals)
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
    print(f"  Base91: {'Available' if HAS_BASE91 else 'Not installed (pip install base91)'}")
    print(f"  Base92: {'Available' if HAS_BASE92 else 'Not installed (pip install base92)'}")
    print("\nAuthor: Joe Schwen (original) + updates")
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
        description="Titan Decoder Engine - Ultimate Edition with 50+ decoders (updated)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
