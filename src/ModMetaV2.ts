import {ScryptOpts} from "@noble/hashes/scrypt.js";

// MagicNumber: JeremieModLoader
export const MagicNumber = new Uint8Array([0x4A, 0x65, 0x72, 0x65, 0x6D, 0x69, 0x65, 0x4D, 0x6F, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72]);
export const ModMetaProtocolVersion = 6; // Version of the mod pack protocol
export const BlockSize = 64; // default block size

export const crypto_stream_chacha20_KEYBYTES = 32;
export const crypto_stream_chacha20_NONCEBYTES = 24;
export const crypto_pwhash_SALTBYTES = 32;

export const scrypt_config = {
    N: 1024,
    r: 4,
    p: 1,
    maxmem: 1024 * 1024 * 10,
    dkLen: crypto_stream_chacha20_KEYBYTES,
} as const satisfies ScryptOpts;

export const GLOBAL_HEADER_SIZE = 128;
export const BLOCK_OFFSET_TABLE_SIZE = 128;

// Flags in Global Header
export enum GlobalFlags {
    None = 0,
    HasEncryptedFiles = 0x1,
    HasCompression = 0x2,
}

// Tree Node Flags
export enum TreeNodeFlags {
    IsFile = 0,
    IsDirectory = 1,
}

// Local Header Magic: "FILE"
export const LocalHeaderMagic = new Uint8Array([0x46, 0x49, 0x4C, 0x45]);

export interface BlockOffsets {
    modMetaOffset: number; // in bytes
    modMetaLength: number;
    bootJsonOffset: number;
    bootJsonLength: number;
    hashIndexOffset: number;
    hashIndexLength: number;
    treeNodeOffset: number;
    treeNodeLength: number;
    stringPoolOffset: number;
    stringPoolLength: number;
    fileStreamOffset: number;
    fileStreamLength: number;
}

