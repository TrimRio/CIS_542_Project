import os
import sys
import struct
from pathlib import Path
from typing import Optional, List, Tuple

# Global variable for program name
try:
    PROGRAM_NAME = os.path.basename(__file__)
except NameError:
    PROGRAM_NAME = os.path.basename(sys.argv[0])

# File signature dictionary (magic bytes)
FILE_SIGNATURES = {
    b'\xFF\xD8\xFF': ('JPEG', '.jpg'),
    b'\x89PNG\r\n\x1a\n': ('PNG', '.png'),
    b'%PDF': ('PDF', '.pdf'),
    b'PK\x03\x04': ('ZIP/DOCX/XLSX', '.zip'),
}

# # other file signatures
# b'GIF87a': ('GIF', '.gif'),
# b'GIF89a': ('GIF', '.gif'),
# b'\x00\x00\x01\x00': ('ICO', '.ico'),
# b'BM': ('BMP', '.bmp'),
# b'RIFF': ('WAV/AVI', '.wav'),

### v3 update add below function

def find_fat32_partition_offset(file_obj):
    """Detect the starting offset (in bytes) of a FAT32 partition from the MBR."""
    file_obj.seek(0)
    mbr = file_obj.read(512)

    # Partition table entries start at byte 446 and there are 4 entries (16 bytes each)
    for i in range(4):
        entry_offset = 446 + i * 16
        entry = mbr[entry_offset:entry_offset + 16]

        partition_type = entry[4]
        start_sector = int.from_bytes(entry[8:12], "little")

        # FAT32 partition types: 0x0B (CHS), 0x0C (LBA)
        if partition_type in (0x0B, 0x0C):
            offset_bytes = start_sector * 512
            print(f"[+] FAT32 partition found at sector {start_sector} (offset {offset_bytes} bytes)")
            return offset_bytes

    print("[-] No FAT32 partition found in MBR; assuming image starts at 0.")
    return 0

class ImageReader:
    """Base class for disk image readers."""

    def read(self, size: int) -> bytes:
        raise NotImplementedError

    def seek(self, offset: int, whence: int = 0):
        raise NotImplementedError

    def tell(self) -> int:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class RawImageReader(ImageReader):
    """Reader for raw disk images."""

    def __init__(self, path: str):
        self.file = open(path, 'rb')

    def read(self, size: int) -> bytes:
        return self.file.read(size)

    def seek(self, offset: int, whence: int = 0):
        return self.file.seek(offset, whence)

    def tell(self) -> int:
        return self.file.tell()

    def close(self):
        self.file.close()


class EWFImageReader(ImageReader):
    """Reader for .e01 (EWF) disk images using pyewf."""

    def __init__(self, path: str):
        try:
            import pyewf
        except ImportError:
            raise ImportError(
                "pyewf library is required for .e01 files.\n"
                "Install it with: pip install libewf-python\n"
                "Note: You may need to install libewf system library first:\n"
                "  Ubuntu/Debian: sudo apt-get install libewf-dev\n"
                "  macOS: brew install libewf\n"
                "  Windows: Download from https://github.com/libyal/libewf/releases"
            )

        # EWF can handle segmented files (.e01, .e02, etc.)
        # Get all segments
        base_path = Path(path)
        self.filenames = [str(base_path)]

        # Check for additional segments (.e02, .e03, etc.)
        for i in range(2, 100):
            segment = base_path.with_suffix(f'.e{i:02d}')
            if segment.exists():
                self.filenames.append(str(segment))
            else:
                break

        print(f"[*] Found {len(self.filenames)} EWF segment(s)")

        self.handle = pyewf.handle()
        self.handle.open(self.filenames)
        self.media_size = self.handle.get_media_size()
        self.position = 0

        print(f"[*] EWF media size: {self.media_size} bytes ({self.media_size / (1024 ** 3):.2f} GB)")

    def read(self, size: int) -> bytes:
        data = self.handle.read(size)
        self.position += len(data)
        return data

    def seek(self, offset: int, whence: int = 0):
        if whence == 0:  # SEEK_SET
            self.position = offset
        elif whence == 1:  # SEEK_CUR
            self.position += offset
        elif whence == 2:  # SEEK_END
            self.position = self.media_size + offset

        self.handle.seek(self.position)
        return self.position

    def tell(self) -> int:
        return self.position

    def close(self):
        self.handle.close()


class FAT32Reader:
    """Minimal FAT32 filesystem reader."""

    def scan_all_directories(self, cluster_num=None, depth=0, results=None, visited=None):
        """
        Recursively scan directory starting at cluster_num, following cluster chains.
        Returns a list of deleted file dicts (name, size, start_cluster, attributes).
        """
        if results is None:
            results = []
        if visited is None:
            visited = set()

        if cluster_num is None:
            cluster_num = self.root_cluster

        if cluster_num in visited:
            return results
        visited.add(cluster_num)

        # Get full cluster chain for this directory
        clusters = self.get_cluster_chain(cluster_num)
        if not clusters:
            # if FAT chain empty, at least try the single cluster
            clusters = [cluster_num]

        entry_size = 32

        for c in clusters:
            cluster_data = self.read_cluster(c)
            num_entries = len(cluster_data) // entry_size
            for i in range(num_entries):
                entry = cluster_data[i * entry_size:(i + 1) * entry_size]
                if len(entry) < 32:
                    continue
                first = entry[0]
                if first == 0x00:
                    # end of entries in this directory cluster
                    continue
                attr = entry[11]
                if attr == 0x0F:
                    # LFN
                    continue

                # deleted file
                if first == 0xE5:
                    cluster_high = struct.unpack("<H", entry[20:22])[0]
                    cluster_low = struct.unpack("<H", entry[26:28])[0]
                    start_cluster = (cluster_high << 16) | cluster_low
                    file_size = struct.unpack("<I", entry[28:32])[0]
                    filename = b'_' + entry[1:8]
                    extension = entry[8:11]
                    filename = filename.rstrip(b' \x00').decode('ascii', errors='replace')
                    extension = extension.rstrip(b' \x00').decode('ascii', errors='replace')
                    full_name = f"{filename}.{extension}" if extension else filename
                    info = {
                        'name': full_name,
                        'size': file_size,
                        'start_cluster': start_cluster,
                        'attributes': attr
                    }
                    results.append(info)
                    print(f"{'  ' * depth}[+] Deleted: {full_name} (cluster {start_cluster}, size {file_size})")

                # subdirectory: follow recursively (skip '.' and '..' entries which usually have cluster 0)
                if attr & 0x10:
                    cluster_high = struct.unpack("<H", entry[20:22])[0]
                    cluster_low = struct.unpack("<H", entry[26:28])[0]
                    subdir_cluster = (cluster_high << 16) | cluster_low
                    if subdir_cluster >= 2 and subdir_cluster not in visited:
                        print(f"{'  ' * depth}[*] Entering subdirectory at cluster {subdir_cluster}")
                        self.scan_all_directories(subdir_cluster, depth + 1, results, visited)

        return results

    def __init__(self, image_path: str):
        self.image_path = image_path

        # Detect image type and create appropriate reader
        ext = Path(image_path).suffix.lower()
        if ext == '.e01':
            print("[*] Detected EWF (.e01) format")
            self.file = EWFImageReader(image_path)
        else:
            print("[*] Detected raw disk image format")
            self.file = RawImageReader(image_path)

        self._parse_boot_sector()

    def _parse_boot_sector(self):
        """Parse FAT32 boot sector to get filesystem parameters and offsets."""
        # Detect and store partition offset (bytes). find_fat32_partition_offset returns bytes.
        self.partition_offset = find_fat32_partition_offset(self.file)

        # Read boot sector at partition start
        self.file.seek(self.partition_offset)
        boot_sector = self.file.read(512)

        # Parse BPB (BIOS Parameter Block)
        self.bytes_per_sector = struct.unpack('<H', boot_sector[11:13])[0]
        self.sectors_per_cluster = boot_sector[13]
        self.reserved_sectors = struct.unpack('<H', boot_sector[14:16])[0]
        self.num_fats = boot_sector[16]
        self.sectors_per_fat = struct.unpack('<I', boot_sector[36:40])[0]
        self.root_cluster = struct.unpack('<I', boot_sector[44:48])[0]

        # Calculate important offsets (include partition offset)
        # FAT starts at partition_offset + reserved_sectors * bytes_per_sector
        self.fat_offset = self.partition_offset + (self.reserved_sectors * self.bytes_per_sector)
        # Data area starts after reserved + all FATs
        self.data_offset = self.partition_offset + ((self.reserved_sectors +
                                                     (self.num_fats * self.sectors_per_fat)) * self.bytes_per_sector)
        self.cluster_size = self.sectors_per_cluster * self.bytes_per_sector

        print(f"[*] FAT32 Image: {self.image_path}")
        print(f"[*] Partition offset: {self.partition_offset} bytes")
        print(f"[*] Bytes per sector: {self.bytes_per_sector}")
        print(f"[*] Sectors per cluster: {self.sectors_per_cluster}")
        print(f"[*] Cluster size: {self.cluster_size} bytes")
        print(f"[*] FAT offset: {self.fat_offset}")
        print(f"[*] Data offset: {self.data_offset}")
        print(f"[*] Root cluster: {self.root_cluster}")

    def read_fat_entry(self, cluster_num: int) -> int:
        """
        Read a FAT32 entry for cluster_num.
        Returns the raw 32-bit entry (masked to 28 bits).
        """
        # FAT32 entries are 4 bytes each
        fat_entry_offset = self.fat_offset + (cluster_num * 4)
        self.file.seek(fat_entry_offset)
        entry_bytes = self.file.read(4)
        if len(entry_bytes) < 4:
            return 0
        entry = int.from_bytes(entry_bytes, "little") & 0x0FFFFFFF
        return entry

    def get_cluster_chain(self, start_cluster: int, max_chain=100000) -> List[int]:
        """
        Follow FAT chain starting at start_cluster and return list of clusters.
        Stops at end-of-chain markers (>= 0x0FFFFFF8) or if chain length exceeds max_chain.
        """
        chain = []
        current = start_cluster
        while current >= 2 and len(chain) < max_chain:
            chain.append(current)
            next_entry = self.read_fat_entry(current)
            if next_entry == 0:
                # cluster marked as free or invalid — stop
                break
            if next_entry >= 0x0FFFFFF8:
                # end-of-chain marker
                break
            # safety: avoid loops
            if next_entry in chain:
                break
            current = next_entry
        return chain

    def read_cluster(self, cluster_num: int) -> bytes:
        """Read a cluster from the data area."""
        # Cluster 2 is the first data cluster
        if cluster_num < 2:
            return b''

        offset = self.data_offset + (cluster_num - 2) * self.cluster_size
        self.file.seek(offset)
        return self.file.read(self.cluster_size)

    def scan_deleted_entries(self, cluster_num: int = None) -> List[dict]:
        """
        Scan for deleted directory entries (0xE5 marker).
        Returns list of deleted file information.
        """
        if cluster_num is None:
            cluster_num = self.root_cluster

        deleted_files = []

        print(f"\n[*] Scanning for deleted directory entries starting at cluster {cluster_num}...")

        # Read directory cluster
        cluster_data = self.read_cluster(cluster_num)
        print(f"[DEBUG] First 64 bytes of root cluster: {cluster_data[:64].hex()}")

        # Each directory entry is 32 bytes
        entry_size = 32
        num_entries = len(cluster_data) // entry_size

        for i in range(num_entries):
            entry_offset = i * entry_size
            entry = cluster_data[entry_offset:entry_offset + entry_size]

            # Check first byte for deleted marker (0xE5)
            if len(entry) < 32:
                continue

            first_byte = entry[0]

            # 0xE5 = deleted file, 0x00 = end of directory, 0x05 = actual 0xE5 in filename
            if first_byte == 0xE5:
                # Parse directory entry
                attr = entry[11]

                # Skip volume labels and LFN entries
                if attr == 0x0F or attr & 0x08:
                    continue

                # Get file information
                # Restore first character (often lost, use '?')
                filename = b'_' + entry[1:8]
                extension = entry[8:11]

                # Clean up filename/extension
                filename = filename.rstrip(b' \x00').decode('ascii', errors='replace')
                extension = extension.rstrip(b' \x00').decode('ascii', errors='replace')

                full_name = f"{filename}.{extension}" if extension else filename

                # Get file size
                file_size = struct.unpack('<I', entry[28:32])[0]

                # Get starting cluster
                cluster_high = struct.unpack('<H', entry[20:22])[0]
                cluster_low = struct.unpack('<H', entry[26:28])[0]
                start_cluster = (cluster_high << 16) | cluster_low

                deleted_file = {
                    'name': full_name,
                    'size': file_size,
                    'start_cluster': start_cluster,
                    'attributes': attr,
                    'is_directory': bool(attr & 0x10)
                }

                deleted_files.append(deleted_file)

                print(f"[+] Found deleted file: {full_name} "
                      f"(Size: {file_size} bytes, Start cluster: {start_cluster})")

        return deleted_files

    def recover_file_by_cluster(self, start_cluster: int, file_size: int, output_path: str):
        """Recover a file by reading from its starting cluster."""
        print(f"[*] Recovering file from cluster {start_cluster}, size {file_size} bytes...")

        recovered_data = b''
        current_cluster = start_cluster
        bytes_remaining = file_size

        # For deleted files, we may not have the FAT chain, so just read sequentially
        while bytes_remaining > 0 and current_cluster >= 2:
            cluster_data = self.read_cluster(current_cluster)

            # Take only what we need
            bytes_to_take = min(len(cluster_data), bytes_remaining)
            recovered_data += cluster_data[:bytes_to_take]
            bytes_remaining -= bytes_to_take

            # Try next cluster (simple sequential recovery)
            current_cluster += 1

            # Safety limit
            if len(recovered_data) >= file_size:
                break

        # Write to output file
        with open(output_path, 'wb') as f:
            f.write(recovered_data)

        print(f"[*] Recovered {len(recovered_data)} bytes to {output_path}")

        # NEW: return data so preview can access it
        return recovered_data

    def preview_data(self, data, num_bytes=256):
        preview = data[:num_bytes]

        # Hex view
        hex_view = " ".join(f"{b:02X}" for b in preview)
        print(hex_view)

        # ASCII view
        ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
        print("\nASCII Preview:")
        print(ascii_view)

        # Quick file type detection
        signatures = {
            b"\xFF\xD8\xFF": "JPEG image",
            b"\x89PNG\r\n\x1A\n": "PNG image",
            b"%PDF": "PDF document",
            b"PK\x03\x04": "ZIP or DOCX/XLSX",
            b"\xD0\xCF\x11\xE0": "MS Office (legacy DOC/XLS)",
            b"BM": "Bitmap image",
            b"\x1F\x8B": "GZIP compressed file",
            b"Rar!": "RAR archive",
            b"\x49\x49\x2A\x00": "TIFF (little endian)",
            b"\x4D\x4D\x00\x2A": "TIFF (big endian)"
        }

        print("\n[*] Detected file type:", end=" ")
        for sig, name in signatures.items():
            if preview.startswith(sig):
                print(name)
                break
        else:
            print("Unknown or plain text")

    def scan_for_signatures(self, start_offset: int = 0, size: Optional[int] = None) -> List[Tuple[int, str, str]]:
        """
        Scan the disk image for file signatures.
        Returns list of (offset, file_type, extension) tuples.
        """
        results = []

        self.file.seek(start_offset)
        if size is None:
            self.file.seek(0, 2)  # Seek to end
            size = self.file.tell() - start_offset
            self.file.seek(start_offset)

        print(f"\n[*] Scanning from offset {start_offset} for {size} bytes...")

        # Read in chunks to handle large images
        chunk_size = 1024 * 1024  # 1MB chunks
        offset = start_offset
        bytes_scanned = 0

        while offset < start_offset + size:
            chunk = self.file.read(min(chunk_size, start_offset + size - offset))
            if not chunk:
                break

            # Progress indicator
            bytes_scanned += len(chunk)
            percent = (bytes_scanned / size) * 100
            print(f"\r[*] Progress: {percent:.1f}%", end='', flush=True)

            # Check for each signature
            for signature, (file_type, extension) in FILE_SIGNATURES.items():
                pos = 0
                while True:
                    pos = chunk.find(signature, pos)
                    if pos == -1:
                        break

                    absolute_offset = offset + pos
                    results.append((absolute_offset, file_type, extension))
                    print(f"\r[+] Found {file_type} at offset {absolute_offset} (0x{absolute_offset:x})")
                    pos += 1

            offset += len(chunk)

        print()  # New line after progress
        return results

    def extract_file(self, offset: int, output_path: str, max_size: int = 10 * 1024 * 1024):
        """Extract a file starting at the given offset."""
        self.file.seek(offset)
        data = self.file.read(max_size)

        with open(output_path, 'wb') as f:
            f.write(data)

        print(f"[*] Extracted {len(data)} bytes to {output_path}")

    def close(self):
        """Close the disk image file."""
        self.file.close()


def main():
    """Main CLI interface."""
    if len(sys.argv) < 2:
        print(f"Usage: python3 {PROGRAM_NAME} <disk_image> [command]")
        print("\nSupported formats:")
        print("  - Raw disk images (.img, .dd, .raw)")
        print("  - Expert Witness Format (.e01, .e02, ...)")
        print("\nCommands:")
        print("  deleted        - Scan for deleted FAT32 directory entries (default)")
        print("  scan           - Scan entire disk for file signatures")
        print("  recover <cluster> <size> <output> - Recover file by cluster and size")
        print("  extract <offset> <output> - Extract file at offset to output path")
        print("\nExample:")
        print(f"  python3 {PROGRAM_NAME} disk.img deleted")
        print(f"  python3 {PROGRAM_NAME} evidence.e01 scan")
        print(f"  python3 {PROGRAM_NAME} disk.img recover 1000 5242880 recovered.jpg")
        print(f"  python3 {PROGRAM_NAME} disk.img extract 1048576 recovered.jpg")
        sys.exit(1)

    image_path = sys.argv[1]

    if not Path(image_path).exists():
        print(f"Error: Image file '{image_path}' not found")
        sys.exit(1)

    try:
        reader = FAT32Reader(image_path)

        for c in range(2, 100):
            data = reader.read_cluster(c)
            if any(b != 0 for b in data):
                print(f"Cluster {c} not empty.")
                break

        command = sys.argv[2] if len(sys.argv) > 2 else "deleted"

        if command == "deleted":
            print("[*] Starting full directory scan for deleted files...\n")
            deleted_files = reader.scan_all_directories()
            print(f"\n[*] Found {len(deleted_files)} deleted file(s)")
            if deleted_files:
                print("\nTo recover a file, run:")
                print(f"  python3 {PROGRAM_NAME} <image> recover <cluster> <size> <output_file>")
                for df in deleted_files[:10]:
                    output_name = df['name'].replace('?', '_')
                    print(f"  python3 {PROGRAM_NAME} {image_path} recover {df['start_cluster']} {df['size']} {output_name}")

        elif command == "scan":
            # Scan data area for file signatures
            results = reader.scan_for_signatures(reader.data_offset)

            print(f"\n[*] Found {len(results)} potential files")
            print("\nTo extract a file, run:")
            print(f"  python3 {PROGRAM_NAME} <image> extract <offset> <output_file>")

        elif command == "recover":
            if len(sys.argv) < 6:
                print(f"Usage: python3 {PROGRAM_NAME} <image> recover <cluster> <size> <output_file>")
                sys.exit(1)

            cluster = int(sys.argv[3])
            size = int(sys.argv[4])
            output_file = sys.argv[5]

            print(f"[*] Recovering {size} bytes starting at cluster {cluster}...")

            data = reader.recover_file_by_cluster(cluster, size, output_file)

            if data:
                print(f"[+] File recovered to: {output_file}")
                print(f"[*] Showing first 256 bytes:\n")
                reader.preview_data(data)

        elif command == "extract":
            if len(sys.argv) < 5:
                print(f"Usage: python3 {PROGRAM_NAME} <image> extract <offset> <output_file>")
                sys.exit(1)

            offset = int(sys.argv[3])
            output_path = sys.argv[4]

            reader.extract_file(offset, output_path)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

        reader.close()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()