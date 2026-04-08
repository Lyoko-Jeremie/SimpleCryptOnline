meta:
  id: modpack_v2
  title: JeremieModLoader ModPack V2
  file-extension: modpack
  endian: le
  ks-version: 0.6

doc: |
  ModPack V2 binary format used by JeremieModLoader.
  Layout:
  - Global header (128 bytes)
  - Block offset table (128 bytes)
  - Variable-sized aligned sections referenced by the offset table

  Length field semantics in block_offset_table:
  - mod_meta_length / boot_json_length : REAL (unpadded) byte count of the UTF-8 payload.
    The physical region is zero-padded to the next 64-byte boundary, but the length
    recorded here reflects only the meaningful content bytes so readers can decode
    without null-byte truncation, even when the payload itself contains NUL characters.
  - All other *_length fields (hash_index, tree_node, string_pool, file_stream) :
    PADDED size (already a multiple of 64).

seq:
  - id: global_header
    type: global_header
  - id: block_offsets
    type: block_offset_table

instances:
  mod_meta_region:
    pos: block_offsets.mod_meta_offset
    size: block_offsets.mod_meta_length
  boot_json_region:
    pos: block_offsets.boot_json_offset
    size: block_offsets.boot_json_length
  hash_index:
    pos: block_offsets.hash_index_offset
    size: block_offsets.hash_index_length
    type: hash_index_array(block_offsets.hash_index_length)
  tree_nodes:
    pos: block_offsets.tree_node_offset
    size: block_offsets.tree_node_length
    type: tree_node_array(block_offsets.tree_node_length)
  string_pool:
    pos: block_offsets.string_pool_offset
    size: block_offsets.string_pool_length
  file_stream:
    pos: block_offsets.file_stream_offset
    size: block_offsets.file_stream_length
    type: file_stream_region

types:
  global_header:
    seq:
      - id: magic
        contents: JeremieModLoader
      - id: protocol_version
        type: u4
      - id: global_flags
        type: u4
      - id: hash_seed
        type: u4
      - id: xchacha20_nonce
        size: 24
      - id: pwhash_salt
        size: 32
      - id: reserved
        size: 44

  block_offset_table:
    doc: |
      Stores offsets and lengths of every major section.
      IMPORTANT: mod_meta_length and boot_json_length are the REAL (unpadded) payload
      lengths.  The physical blocks are zero-padded to 64-byte boundaries, but the
      length values here reflect only the meaningful content bytes.  All other
      *_length fields are already multiples of 64 (padded sizes).
    seq:
      - id: mod_meta_offset
        type: u4
        doc: Byte offset of the ModMeta JSON region.
      - id: mod_meta_length
        type: u4
        doc: REAL byte length of the ModMeta JSON payload (not 64-byte-aligned).
      - id: boot_json_offset
        type: u4
        doc: Byte offset of the boot.json region.
      - id: boot_json_length
        type: u4
        doc: REAL byte length of the boot.json payload (not 64-byte-aligned).
      - id: hash_index_offset
        type: u4
      - id: hash_index_length
        type: u4
        doc: Padded size (multiple of 64).
      - id: tree_node_offset
        type: u4
      - id: tree_node_length
        type: u4
        doc: Padded size (multiple of 64).
      - id: string_pool_offset
        type: u4
      - id: string_pool_length
        type: u4
        doc: Padded size (multiple of 64).
      - id: file_stream_offset
        type: u4
      - id: file_stream_length
        type: u4
      - id: reserved
        size: 80

  hash_index_array:
    params:
      - id: byte_len
        type: u4
    seq:
      - id: entries
        type: hash_index_entry
        repeat: expr
        repeat-expr: byte_len / 16

  hash_index_entry:
    seq:
      - id: hash_value
        type: u8
      - id: block_index
        type: u4
      - id: flags
        type: u4

  tree_node_array:
    params:
      - id: byte_len
        type: u4
    seq:
      - id: nodes
        type: tree_node_entry
        repeat: expr
        repeat-expr: byte_len / 32

  tree_node_entry:
    seq:
      - id: name_offset
        type: u4
      - id: name_length
        type: u2
      - id: flags
        type: u2
      - id: local_hash
        type: u4
      - id: target_index
        type: u4
      - id: target_size
        type: u4
      - id: reserved
        size: 12

  file_stream_region:
    seq:
      - id: entries
        type: file_stream_entry
        repeat: eos

  file_stream_entry:
    seq:
      - id: local_header
        type: local_header
      - id: file_data
        size: local_header.real_length
      - id: file_data_padding
        size: (64 - (local_header.real_length % 64)) % 64

  local_header:
    seq:
      - id: magic
        contents: FILE
      - id: name_length
        type: u2
      - id: real_length
        type: u4
      - id: flags
        type: u2
      - id: full_path
        type: str
        size: name_length
        encoding: UTF-8
      - id: xxhash64
        type: u8
      - id: header_padding
        size: (64 - ((20 + name_length) % 64)) % 64



