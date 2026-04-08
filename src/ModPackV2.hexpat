/**
 * ImHex Pattern: JeremieModLoader ModPack V2
 *
 * Spec references:
 *   - ModPackV2.md  — human-readable design document
 *   - ModPackV2.ksy — Kaitai Struct definition
 *
 * File layout (all sections except Global Header are 64-byte aligned):
 *
 *   [ Global Header         ]  128 bytes  @ 0x000
 *   [ Block Offset Table    ]  128 bytes  @ 0x080
 *   [ ModMeta JSON          ]  variable   @ block_offsets.mod_meta_offset
 *   [ boot.json             ]  variable   @ block_offsets.boot_json_offset
 *   [ Hash Index Array      ]  variable   @ block_offsets.hash_index_offset
 *   [ Tree Node Array       ]  variable   @ block_offsets.tree_node_offset
 *   [ String Pool           ]  variable   @ block_offsets.string_pool_offset
 *   [ File Stream Region    ]  variable   @ block_offsets.file_stream_offset
 */

#pragma description "JeremieModLoader ModPack V2"
#pragma endian little
#pragma magic [ 4A 65 72 65 6D 69 65 4D 6F 64 4C 6F 61 64 65 72 ] @ 0x00

import std.mem;
import std.string;

// ─── Bitfields ───────────────────────────────────────────────────────────────

/// Global flags stored in GlobalHeader.global_flags
bitfield GlobalFlags {
    has_encrypted_files : 1;   // bit 0: package contains at least one encrypted file
    has_compression     : 1;   // bit 1: compression is supported/used
    reserved            : 30;
};

/// Per-node flags in TreeNodeEntry.flags
bitfield TreeNodeFlags {
    is_directory : 1;   // bit 0: 1 = directory node, 0 = file node
    reserved     : 15;
};

/// Per-file flags in LocalHeader.flags
bitfield FileEntryFlags {
    is_encrypted : 1;   // bit 0: file payload is XChaCha20-encrypted
    reserved     : 15;
};

// ─── Global Header (fixed 128 bytes @ 0x00) ──────────────────────────────────

/// Identifies the file and declares global cryptographic parameters.
struct GlobalHeader {
    char        magic[16]            [[comment("Magic bytes: \"JeremieModLoader\"")]];
    u32         protocol_version     [[comment("Format protocol version (little-endian u32)")]];
    GlobalFlags global_flags         [[comment("Bitmask: bit0=encrypted, bit1=compression")]];
    u32         hash_seed            [[comment("Seed used for xxHash64 perfect-hash construction")]];
    u8          xchacha20_nonce[24]  [[comment("Raw XChaCha20 nonce (24 bytes)")]];
    u8          pwhash_salt[32]      [[comment("Password-based KDF salt (32 bytes)")]];
    u8          reserved[44]         [[comment("Reserved; must be zero")]];
} [[
    color("4A90D9"),
    comment("Global file header — 128 bytes")
]];

// ─── Block Offset Table (fixed 128 bytes @ 0x80) ─────────────────────────────

/**
 * Stores byte offsets and lengths for every major section.
 *
 * IMPORTANT length semantics:
 *   mod_meta_length / boot_json_length  → REAL (unpadded) payload byte count.
 *     The physical block is zero-padded to a 64-byte boundary, but only
 *     [0 .. length) bytes are meaningful content.
 *   All other *_length fields           → PADDED size (already a multiple of 64).
 */
struct BlockOffsetTable {
    u32 mod_meta_offset     [[comment("Byte offset of ModMeta JSON region")]];
    u32 mod_meta_length     [[comment("REAL (unpadded) byte length of ModMeta JSON payload")]];
    u32 boot_json_offset    [[comment("Byte offset of boot.json region")]];
    u32 boot_json_length    [[comment("REAL (unpadded) byte length of boot.json payload")]];
    u32 hash_index_offset   [[comment("Byte offset of Hash Index Array")]];
    u32 hash_index_length   [[comment("PADDED size of Hash Index Array (multiple of 64)")]];
    u32 tree_node_offset    [[comment("Byte offset of Tree Node Array")]];
    u32 tree_node_length    [[comment("PADDED size of Tree Node Array (multiple of 64)")]];
    u32 string_pool_offset  [[comment("Byte offset of String Pool")]];
    u32 string_pool_length  [[comment("PADDED size of String Pool (multiple of 64)")]];
    u32 file_stream_offset  [[comment("Byte offset of File Stream Region")]];
    u32 file_stream_length  [[comment("Total byte length of File Stream Region")]];
    u8  reserved[80]        [[comment("Reserved; must be zero")]];
} [[
    color("E67E22"),
    comment("Block offset table — 128 bytes")
]];

// ─── Central Index ────────────────────────────────────────────────────────────

/**
 * Hash Index Entry — 16 bytes per entry.
 *
 * The array is sorted by hash_value to allow binary search.
 * hash_value = xxHash64(full_unix_path, HashSeed)
 * The array is guaranteed collision-free: if a collision is detected during
 * packing, HashSeed is changed and the entire array is rebuilt.
 */
struct HashIndexEntry {
    u64 hash_value   [[comment("xxHash64(full_path, HashSeed) — unique, no collisions")]];
    u32 block_index  [[comment("64-byte block index of the corresponding Local Header")]];
    u32 flags        [[comment("Reserved / fast status bits")]];
} [[comment("Hash index entry — 16 bytes")]];

/**
 * Tree Node Entry — 32 bytes per node.
 *
 * The array encodes the entire directory tree in a flat, sorted layout:
 *   - Root node is always at index 0.
 *   - All children of a directory are stored consecutively and sorted by
 *     local name (lexicographic order), enabling O(log N) binary search.
 */
struct TreeNodeEntry {
    u32           name_offset   [[comment("Byte offset of local name inside String Pool")]];
    u16           name_length   [[comment("Byte length of local name (UTF-8, no null terminator)")]];
    TreeNodeFlags flags         [[comment("bit0: 1=directory, 0=file")]];
    u32           local_hash    [[comment("Short hash of local name (speeds up binary search)")]];
    u32           target_index  [[comment("Dir → child-start index in TreeNodeArray; File → Local Header block index")]];
    u32           target_size   [[comment("Dir → child count; File → real data byte length")]];
    u8            reserved[12]  [[comment("Reserved; must be zero")]];
} [[comment("Tree node entry — 32 bytes")]];

// ─── File Stream Region ───────────────────────────────────────────────────────

/**
 * Local Header — variable length, always starts on a 64-byte boundary.
 *
 * Fixed part (20 bytes):
 *   magic(4) + name_length(2) + real_length(4) + flags(2) + xxhash64(8)
 *
 * Followed by:
 *   full_path (name_length bytes, UTF-8, no leading slash, no null terminator)
 *   xxhash64  (8 bytes, uint64) - integrity verification
 *   padding   = (64 - ((20 + name_length) % 64)) % 64  zero bytes
 *               → ensures the immediately following File Data starts on a
 *                 fresh 64-byte boundary (= a new XChaCha20 block counter).
 */
struct LocalHeader {
    char           magic[4]       [[comment("Magic: \"FILE\"")]];
    u16            name_length     [[comment("Byte length of full_path")]];
    u32            real_length     [[comment("True byte length of the file payload")]];
    FileEntryFlags flags           [[comment("bit0: 1=encrypted (XChaCha20)")]];
    char           full_path[name_length]
                                  [[comment("Full UNIX-style path, UTF-8 (e.g. \"textures/ui/icon.png\")")]];
    u64            xxhash64       [[comment("xxHash64 of the original (unencrypted) file payload")]];
    u8             header_padding[(64 - ((20 + name_length) % 64)) % 64]
                                  [[comment("Zero padding — aligns File Data to the next 64-byte boundary")]];
} [[comment("Local file header (variable length, 64-byte-boundary-aligned)")]];

/**
 * One entry in the File Stream Region.
 *
 * XChaCha20 decryption note:
 *   The initial counter for decrypting `data` MUST equal the 64-byte block
 *   index at which `data` begins inside the file (i.e. addressof(data) / 64).
 */
struct FileStreamEntry {
    LocalHeader header;
    u8 data[header.real_length]
                                  [[comment("File payload — plaintext or XChaCha20 ciphertext")]];
    u8 data_padding[(64 - (header.real_length % 64)) % 64]
                                  [[comment("Zero padding — aligns next Local Header to 64-byte boundary")]];
} [[comment("File stream entry (Local Header + payload + padding)")]];

// ─── Top-level Placement ──────────────────────────────────────────────────────

GlobalHeader     global_header @ 0x00;
BlockOffsetTable block_offsets @ 0x80;

// ── ModMeta JSON ──────────────────────────────────────────────────────────────
// Real (unpadded) payload; physical region is zero-padded to 64-byte boundary.
char mod_meta_json[block_offsets.mod_meta_length] @ block_offsets.mod_meta_offset
    [[
        color("2ECC71"),
        comment("ModMeta JSON payload (real length; trailing zeros are padding)")
    ]];

// ── boot.json ─────────────────────────────────────────────────────────────────
char boot_json_str[block_offsets.boot_json_length] @ block_offsets.boot_json_offset
    [[
        color("27AE60"),
        comment("boot.json payload (real length; trailing zeros are padding)")
    ]];

// ── Hash Index Array ──────────────────────────────────────────────────────────
// Entry count = padded_length / 16 (each entry is 16 bytes).
HashIndexEntry hash_index[block_offsets.hash_index_length / 16]
    @ block_offsets.hash_index_offset
    [[
        color("9B59B6"),
        comment("Hash Index Array — O(1) full-path lookup via xxHash64")
    ]];

// ── Tree Node Array ───────────────────────────────────────────────────────────
// Entry count = padded_length / 32 (each node is 32 bytes).
TreeNodeEntry tree_nodes[block_offsets.tree_node_length / 32]
    @ block_offsets.tree_node_offset
    [[
        color("1ABC9C"),
        comment("Tree Node Array — flat sorted tree for directory traversal")
    ]];

// ── String Pool ───────────────────────────────────────────────────────────────
// Raw bytes; use TreeNodeEntry.name_offset + name_length to slice individual names.
u8 string_pool[block_offsets.string_pool_length]
    @ block_offsets.string_pool_offset
    [[
        color("F39C12"),
        comment("String Pool — packed local file names (UTF-8, no null terminators)")
    ]];

// ── File Stream Region ────────────────────────────────────────────────────────
// Iterate until the end of the declared file_stream_length.
FileStreamEntry file_stream[while($ < block_offsets.file_stream_offset + block_offsets.file_stream_length)]
    @ block_offsets.file_stream_offset
    [[
        color("E74C3C"),
        comment("File Stream Region — Local Headers interleaved with padded file payloads")
    ]];

