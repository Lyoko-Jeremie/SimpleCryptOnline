/**
 * ModPackV2.ts — JeremieModLoader (JML) 封包文件 V2 实现
 *
 * 本文件实现了一套面向数据设计 (Data-Oriented Design) 的现代混合索引虚拟文件系统架构，
 * 核心目标包括：
 *   1. 极致零拷贝 (Zero-Copy) — 通过 TypedArray/DataView 视图映射消除反序列化开销
 *   2. 完美的原地加解密 — 强制 64 字节块对齐，契合 XChaCha20 的内部计数器
 *   3. 混合查询能力 — O(1) 全路径哈希定位 + O(log N) 目录内二分查找 + 完整 JS 对象树
 *   4. 灾难恢复 — Local Header 保留完整路径明文，便于 Hex 审查与索引重建
 *
 * 整体文件布局 (详见 ModPackV2.md):
 * ┌──────────────────────────────────────────────┐
 * │ Global Header            (128 bytes, 定长)    │
 * ├──────────────────────────────────────────────┤
 * │ Block Offset Table       (128 bytes, 定长)    │  ← 记录下方各区块的偏移与长度
 * ├──────────────────────────────────────────────┤
 * │ ModMeta JSON             (64B 对齐, 明文)     │  ← 文件元数据（算法参数/Nonce 等）
 * ├──────────────────────────────────────────────┤
 * │ boot.json                (64B 对齐, 明文)     │  ← 引导信息
 * ├──────────────────────────────────────────────┤
 * │ Hash Index Array         (64B 对齐)           │  ← O(1) 全路径定位（xxHash64）
 * ├──────────────────────────────────────────────┤
 * │ Tree Node Array          (64B 对齐)           │  ← 拍平的树状节点（目录遍历/二分查找）
 * ├──────────────────────────────────────────────┤
 * │ String Pool              (64B 对齐)           │  ← 局部文件名字符串池
 * ├──────────────────────────────────────────────┤
 * │ File Stream Region                            │  ← Local Header + File Data 交替排列
 * │   ├─ [Local Header 1] (64B 对齐, 含完整路径)  │
 * │   ├─ [File Data 1]    (64B 对齐)              │
 * │   ├─ [Local Header 2] ...                     │
 * │   └─ ...                                      │
 * └──────────────────────────────────────────────┘
 */
import {
    BlockOffsets,
    BlockSize,
    GLOBAL_HEADER_SIZE,
    BLOCK_OFFSET_TABLE_SIZE,
    GlobalFlags,
    LocalHeaderMagic,
    MagicNumber,
    ModMetaProtocolVersion,
    TreeNodeFlags, crypto_stream_chacha20_KEYBYTES, crypto_pwhash_SALTBYTES, crypto_stream_chacha20_NONCEBYTES
} from "./ModMetaV2";
import xxhash, {XXHashAPI} from "xxhash-wasm";
import JSZip from "jszip";

import argon2 from 'argon2-browser';
import {xchacha20} from '@noble/ciphers/chacha.js';
import {randombytes_buf} from "./randombytes_buf";

// Local Header flags
const LH_FLAG_ENCRYPTED = 1;

// Random bytes helper (browser-friendly)
function getRandomBytes(length: number): Uint8Array {
    // if (typeof globalThis !== 'undefined' && (globalThis as any).crypto && (globalThis as any).crypto.getRandomValues) {
    //     const arr = new Uint8Array(length);
    //     (globalThis as any).crypto.getRandomValues(arr);
    //     return arr;
    // }
    // // Fallback to Node.js if available
    // try {
    //     // eslint-disable-next-line @typescript-eslint/no-var-requires
    //     const nodeCrypto = require('crypto');
    //     return new Uint8Array(nodeCrypto.randomBytes(length));
    // } catch {
    //     throw new Error('No secure random generator available');
    // }
    return randombytes_buf(length, 'uint8array');
}

/**
 * JsFileNode — 表示 JS 内存中的文件/目录树节点
 *
 * 由 ZeroCopyTree.buildJsObjectTree() 从零拷贝视图中提取生成，
 * 可用于 UI 文件树展示等常规 JavaScript 使用场景。
 */
export interface JsFileNode {
    name: string;
    isFile: boolean;
    size?: number;             // 仅文件有：文件的真实字节长度
    blockIndex?: number;       // 仅文件有：对应 Local Header 的绝对块编号
    children?: Record<string, JsFileNode>; // 仅目录有：子节点映射表（局部名 → 节点）
}

/**
 * ZeroCopyTree — 零拷贝目录树视图
 *
 * 直接操作 Tree Node Array 和 String Pool 的二进制缓冲区，
 * 无需反序列化即可实现目录枚举、二分查找和完整树构建。
 *
 * Tree Node Array 结构（每节点 32 字节）:
 *   [0..3]   name_offset  (uint32) — 局部名在 String Pool 中的字节偏移
 *   [4..5]   name_length  (uint16) — 局部名的字节长度
 *   [6..7]   flags        (uint16) — bit 0: 1=目录, 0=文件
 *   [8..11]  local_hash   (uint32) — 局部名短哈希（保留）
 *   [12..15] target_index (uint32) — 目录: 子节点起始下标 / 文件: Local Header 块编号
 *   [16..19] target_size  (uint32) — 目录: 子节点数量 / 文件: 真实字节长度
 *   [20..31] reserved     (12 bytes)
 *
 * 铁律：
 *   1. 物理连续性 — 同一目录的子节点在数组中必须紧挨
 *   2. 字典序排列 — 子节点按局部文件名字典序排列，以支持 O(log N) 二分查找
 */
export class ZeroCopyTree {
    private treeData: DataView;
    private stringPool: Uint8Array;
    private decoder = new TextDecoder('utf-8');

    constructor(treeBuffer: ArrayBuffer | Uint8Array, poolBuffer: ArrayBuffer | Uint8Array) {
        if (treeBuffer instanceof Uint8Array) {
            this.treeData = new DataView(treeBuffer.buffer, treeBuffer.byteOffset, treeBuffer.length);
        } else {
            this.treeData = new DataView(treeBuffer);
        }

        if (poolBuffer instanceof Uint8Array) {
            this.stringPool = poolBuffer;
        } else {
            this.stringPool = new Uint8Array(poolBuffer);
        }
    }

    /**
     * 从 String Pool 中读取指定节点的局部文件名
     * @param nodeIndex 节点在 Tree Node Array 中的索引
     */
    private readLocalName(nodeIndex: number): string {
        // 每个节点 32 字节，name_offset 在偏移 0，name_length 在偏移 4
        const offset = nodeIndex * 32;
        const nameOffset = this.treeData.getUint32(offset, true);
        const nameLength = this.treeData.getUint16(offset + 4, true);
        return this.decoder.decode(this.stringPool.subarray(nameOffset, nameOffset + nameLength));
    }

    /**
     * 就地读取目录内容（类似 fs.readdir）
     *
     * 直接从二进制视图中枚举目录的所有子节点名称，
     * 不产生任何中间对象分配（除了返回的字符串数组）。
     *
     * @param dirNodeIndex 目录节点在 Tree Node Array 中的索引（默认 0 = 根目录）
     * @returns 子节点局部名数组（已按字典序排列）
     */
    public readDirInPlace(dirNodeIndex: number = 0): string[] {
        const offset = dirNodeIndex * 32;
        const isDir = (this.treeData.getUint16(offset + 6, true) & 1) === 1;
        if (!isDir) throw new Error("Not a directory");

        // target_index (offset+12) = 子节点起始下标
        // target_size  (offset+16) = 子节点数量
        const childStart = this.treeData.getUint32(offset + 12, true);
        const childCount = this.treeData.getUint32(offset + 16, true);

        const list = [];
        for (let i = 0; i < childCount; i++) {
            list.push(this.readLocalName(childStart + i));
        }
        return list;
    }

    /**
     * 在目录内通过二分查找定位子节点
     *
     * 利用子节点按字典序排列的铁律，实现 O(log N) 的局部查找。
     *
     * @param dirNodeIndex 目录节点索引
     * @param targetName 要查找的局部文件名
     * @returns 找到的子节点索引，未找到返回 null
     */
    public findChildInPlace(dirNodeIndex: number, targetName: string): number | null {
        const offset = dirNodeIndex * 32;
        const isDir = (this.treeData.getUint16(offset + 6, true) & 1) === 1;
        if (!isDir) return null;

        const childStart = this.treeData.getUint32(offset + 12, true);
        const childCount = this.treeData.getUint32(offset + 16, true);

        // 二分查找：子节点按字典序排列
        let lo = 0, hi = childCount - 1;
        while (lo <= hi) {
            const mid = (lo + hi) >>> 1;
            const midName = this.readLocalName(childStart + mid);
            const cmp = midName.localeCompare(targetName);
            if (cmp === 0) return childStart + mid;
            if (cmp < 0) lo = mid + 1;
            else hi = mid - 1;
        }
        return null;
    }

    /**
     * 从零拷贝视图中提取完整的 JavaScript 嵌套对象树
     *
     * 递归遍历 Tree Node Array，生成常规 JS 对象树（JsFileNode）。
     * 适用于需要完整树结构的场景（如 UI 文件浏览器）。
     *
     * @param nodeIndex 起始节点索引（默认 0 = 根目录）
     */
    public buildJsObjectTree(nodeIndex: number = 0): JsFileNode {
        const offset = nodeIndex * 32;
        const flags = this.treeData.getUint16(offset + 6, true);
        const isDir = (flags & 1) === 1;

        const node: JsFileNode = {
            name: this.readLocalName(nodeIndex),
            isFile: !isDir
        };

        // target_index / target_size 的含义取决于节点类型
        const targetIndex = this.treeData.getUint32(offset + 12, true);
        const targetSize = this.treeData.getUint32(offset + 16, true);

        if (isDir) {
            // 目录: targetIndex = 子节点起始下标, targetSize = 子节点数量
            node.children = {};
            for (let i = 0; i < targetSize; i++) {
                const childNodeIndex = targetIndex + i;
                const childObj = this.buildJsObjectTree(childNodeIndex);
                node.children[childObj.name] = childObj;
            }
        } else {
            // 文件: targetIndex = Local Header 块编号, targetSize = 真实字节长度
            node.blockIndex = targetIndex;
            node.size = targetSize;
        }

        return node;
    }
}

/**
 * ModPackerV2 — V2 封包文件打包器
 *
 * 负责将一组文件打包为符合 JML V2 规范的二进制封包。
 * 打包流程概要：
 *   1. 路径标准化（UNIX 风格正斜杠，无前导/后置斜杠）
 *   2. 构建拍平的树状节点数组（BFS 层序遍历，子节点字典序排列）
 *   3. 构建完美哈希索引（自动调整 HashSeed 直到无冲突）
 *   4. 生成文件流区（Local Header + File Data 交替，全部 64B 对齐）
 *   5. 组装全局头、偏移表和所有区块
 */
export class ModPackerV2 {
    private encoder = new TextEncoder();
    private xxhashApi: XXHashAPI;

    constructor(xxhashApi: XXHashAPI) {
        this.xxhashApi = xxhashApi;
    }

    public static async create(): Promise<ModPackerV2> {
        const api = await xxhash();
        return new ModPackerV2(api);
    }

    /**
     * 路径标准化：反斜杠转正斜杠，去除前导/后置斜杠
     * 例如: "\\a\\b\\c\\" → "a/b/c"
     */
    private normalizePath(path: string): string {
        return path.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    }

    /**
     * 将文件集合打包为 V2 封包格式的二进制数据
     *
     * @param files     文件路径 → 文件内容的映射
     * @param modMetaJson  ModMeta JSON 字符串（算法参数/Nonce 等元数据）
     * @param bootJson     boot.json 引导信息 JSON 字符串
     * @param options      可选参数，hashSeed 可指定初始哈希种子
     * @returns 打包后的完整二进制数据
     */
    public async pack(
        files: Map<string, Uint8Array>,
        modMetaJson: string,
        bootJson: string,
        options: { hashSeed?: number, password?: string } = {}
    ): Promise<Uint8Array> {
        // ── 第一步：路径标准化，确保 boot.json 使用传入的 bootJson 参数 ──
        const normalizedFiles = new Map<string, Uint8Array>();
        for (const [path, data] of files) {
            const norm = this.normalizePath(path);
            if (norm === "boot.json") continue; // 跳过文件集合中的 boot.json，使用参数传入的
            normalizedFiles.set(norm, data);
        }
        normalizedFiles.set("boot.json", this.encoder.encode(bootJson));

        // ── 加密参数准备（若提供了密码，则对文件体启用 XChaCha20 原地加密）──
        const hasEncrypted = !!options.password;
        const nonce = hasEncrypted ? getRandomBytes(crypto_stream_chacha20_NONCEBYTES) : new Uint8Array(crypto_stream_chacha20_NONCEBYTES);
        const salt = hasEncrypted ? getRandomBytes(crypto_pwhash_SALTBYTES) : new Uint8Array(crypto_pwhash_SALTBYTES);
        let key: Uint8Array | null = null;
        if (hasEncrypted && options.password) {
            const kdf = await argon2.hash({
                pass: options.password,
                salt,
                // time: 3,
                // mem: 1 << 16, // 64 MiB
                // parallelism: 1,
                hashLen: crypto_stream_chacha20_KEYBYTES,
                // type: (argon2 as any).ArgonType?.Argon2id ?? 2, // prefer Argon2id
            } as any);
            // argon2-browser returns { hash: ArrayBuffer | Uint8Array }
            const hashBuf: ArrayBuffer | Uint8Array = (kdf as any).hash;
            key = hashBuf instanceof Uint8Array ? hashBuf : new Uint8Array(hashBuf);
        }

        // ── 第二步：构建内存中的目录树 ──
        const sortedPaths = Array.from(normalizedFiles.keys()).sort();
        const root: any = {name: "", children: new Map(), isFile: false};
        for (const path of sortedPaths) {
            const parts = path.split('/');
            let current = root;
            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                if (!current.children.has(part)) {
                    current.children.set(part, {
                        name: part,
                        children: new Map(),
                        isFile: i === parts.length - 1
                    });
                }
                current = current.children.get(part);
            }
        }

        // ── 第三步：BFS 层序遍历，构建拍平的 Tree Node Array ──
        // 保证铁律：同一目录的子节点物理连续 + 字典序排列
        const treeNodes: any[] = [];
        const stringPoolParts: Uint8Array[] = [];
        let currentStringOffset = 0;

        const processNode = (node: any, parent: any = null) => {
            const nodeIdx = treeNodes.length;
            treeNodes.push(node);
            node.index = nodeIdx;
            node.parent = parent;

            // 将局部名写入 String Pool
            const nameBuf = this.encoder.encode(node.name);
            node.nameOffset = currentStringOffset;
            node.nameLength = nameBuf.length;
            stringPoolParts.push(nameBuf);
            currentStringOffset += nameBuf.length;

            if (!node.isFile) {
                // 子节点按字典序排列（铁律 #2）
                const sortedChildren = Array.from(node.children.values())
                    .sort((a: any, b: any) => a.name.localeCompare(b.name));
                node.childStart = 0; // 占位，BFS 中会重新赋值
                node.childCount = sortedChildren.length;
                node.sortedChildren = sortedChildren;
            }
        };

        // BFS 遍历确保同一目录的子节点在数组中物理连续（铁律 #1）
        const queue: { node: any, parent: any }[] = [{node: root, parent: null}];
        let head = 0;
        while (head < queue.length) {
            const {node, parent} = queue[head++];
            processNode(node, parent);
            if (!node.isFile) {
                // childStart = 子节点在 Tree Node Array 中的起始下标
                node.childStart = queue.length;
                for (const child of node.sortedChildren) {
                    queue.push({node: child, parent: node});
                }
            }
        }

        // String Pool：局部名首尾相连，不使用 \0 结尾，依靠 offset+length 切片读取
        const stringPoolBuffer = this.concatUint8Arrays(stringPoolParts);
        const stringPoolPadded = this.padToBlockSize(new Uint8Array(stringPoolBuffer));

        // 各元数据区块对齐到 64 字节边界
        const modMetaRawBuf = this.encoder.encode(modMetaJson);
        const bootJsonRawBuf = this.encoder.encode(bootJson);
        const modMetaBuf = this.padToBlockSize(modMetaRawBuf);
        const bootJsonBuf = this.padToBlockSize(bootJsonRawBuf);
        const treeNodeArraySize = this.alignTo64(treeNodes.length * 32);

        // ── 第四步：构建完美哈希索引 ──
        // 自动调整 HashSeed 直到所有文件路径的 xxHash64 无冲突
        let hashSeed = options.hashSeed || Math.floor(Math.random() * 0xFFFFFFFF);
        const entryCount = this.alignTo64(sortedPaths.length * 16) / 16;
        let finalHashIndex = new Uint8Array(entryCount * 16);

        // 尝试构建无冲突的哈希表，若有冲突则递增 seed 重试
        while (true) {
            const slots = new Array(entryCount).fill(null);
            let collision = false;
            for (let i = 0; i < sortedPaths.length; i++) {
                const path = sortedPaths[i];
                const h = this.xxhashApi.h64(path, BigInt(hashSeed));
                const slotIdx = Number(h % BigInt(entryCount));
                if (slots[slotIdx] !== null) {
                    collision = true;
                    break;
                }
                slots[slotIdx] = {h, path};
            }
            if (!collision) break;
            hashSeed = (hashSeed + 1) >>> 0;
        }

        // ── 第五步：计算文件流区的起始偏移 ──
        // baseOffset = Global Header + Block Offset Table + ModMeta + BootJson
        //            + Hash Index + Tree Node Array + String Pool
        const baseOffset = GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE +
            modMetaBuf.length + bootJsonBuf.length +
            finalHashIndex.length + treeNodeArraySize + stringPoolPadded.length;

        // ── 第六步：构建文件流区（Local Header + File Data 交替排列）──
        let currentAbsoluteOffset = baseOffset;
        const fileStreamChunks: Uint8Array[] = [];
        const fileEntries: { path: string, blockIndex: number, size: number }[] = [];

        for (const path of sortedPaths) {
            const data = normalizedFiles.get(path)!;
            const pathBuf = this.encoder.encode(path);
            // Local Header 大小 = 20 字节固定头(含8字节xxhash) + 路径长度，对齐到 64 字节
            const localHeaderSize = this.alignTo64(20 + pathBuf.length);

            // Block Index = 绝对字节偏移 / 64（块编号）
            // 可直接用作 XChaCha20 解密时的初始 Counter
            const blockIndex = currentAbsoluteOffset / BlockSize;
            fileEntries.push({path, blockIndex, size: data.length});

            // 计算明文 xxHash64（用于完整性校验）
            const fileHash = this.xxhashApi.h64Raw(data, BigInt(0));

            // 构建 Local Header:
            //   [0..3]  magic "FILE" (4 bytes)
            //   [4..5]  name_length  (uint16)
            //   [6..9]  real_length  (uint32) — 文件原始数据真实长度
            //   [10..11] flags       (uint16) — bit0=加密
            //   [12..(12+nameLen-1)] full_path (UTF-8, 含斜杠完整路径)
            //   [(12+nameLen)..(19+nameLen)] xxhash64 (uint64, 明文数据)
            //   尾部 0x00 填充至 64 字节边界
            const lh = new Uint8Array(localHeaderSize);
            lh.set(LocalHeaderMagic);
            const lhView = new DataView(lh.buffer);
            lhView.setUint16(4, pathBuf.length, true);
            lhView.setUint32(6, data.length, true);
            lhView.setUint16(10, hasEncrypted ? LH_FLAG_ENCRYPTED : 0, true);
            lh.set(pathBuf, 12);
            lhView.setBigUint64(12 + pathBuf.length, fileHash, true);
            fileStreamChunks.push(lh);

            // File Data：严格从 64 字节边界起算，尾部 0x00 填充到下一个 64 字节边界
            let outData = data;
            if (hasEncrypted && key) {
                outData = xchacha20(key, nonce, data, undefined, blockIndex);
            }
            fileStreamChunks.push(outData);
            const dataPadding = (BlockSize - (outData.length % BlockSize)) % BlockSize;
            if (dataPadding > 0) fileStreamChunks.push(new Uint8Array(dataPadding));
            currentAbsoluteOffset += localHeaderSize + outData.length + dataPadding;
        }

        const fileStreamBuffer = this.concatUint8Arrays(fileStreamChunks);

        // ── 第七步：填充 Hash Index Array ──
        // 每个条目 16 字节: hash_value(uint64) + block_index(uint32) + flags(uint32)
        const hashIndexView = new DataView(finalHashIndex.buffer);
        for (const entry of fileEntries) {
            const h = this.xxhashApi.h64(entry.path, BigInt(hashSeed));
            const slotIdx = Number(h % BigInt(entryCount));
            const off = slotIdx * 16;
            hashIndexView.setBigUint64(off, h, true);          // hash_value
            hashIndexView.setUint32(off + 8, entry.blockIndex, true); // block_index
        }

        // ── 第八步：填充 Tree Node Array ──
        // 每个节点 32 字节，详见 ZeroCopyTree 类注释
        const finalTreeNodeArray = new Uint8Array(treeNodes.length * 32);
        const treeNodeView = new DataView(finalTreeNodeArray.buffer);
        for (let i = 0; i < treeNodes.length; i++) {
            const node = treeNodes[i];
            const offset = i * 32;
            treeNodeView.setUint32(offset, node.nameOffset, true);       // name_offset
            treeNodeView.setUint16(offset + 4, node.nameLength, true);   // name_length
            treeNodeView.setUint16(offset + 6, node.isFile ? TreeNodeFlags.IsFile : TreeNodeFlags.IsDirectory, true); // flags
            if (node.isFile) {
                // 文件: target_index = block_index, target_size = real_length
                const fullPath = this.getFullPath(node);
                const entry = fileEntries.find(e => e.path === fullPath);
                treeNodeView.setUint32(offset + 12, entry!.blockIndex, true);
                treeNodeView.setUint32(offset + 16, entry!.size, true);
            } else {
                // 目录: target_index = child_start, target_size = child_count
                treeNodeView.setUint32(offset + 12, node.childStart, true);
                treeNodeView.setUint32(offset + 16, node.childCount, true);
            }
        }

        // Tree Node Array 也需对齐到 64 字节边界
        const finalTreeNodeArrayPadded = this.padToBlockSize(finalTreeNodeArray);

        // ── 第九步：构建 Global Header (128 字节) ──
        // 0x00~0x0F: Magic Number "JeremieModLoader"
        // 0x10~0x13: 协议版本号
        // 0x14~0x17: 标志位掩码
        // 0x18~0x1B: HashSeed（完美哈希种子）
        // 0x1C~0x7F: 预留（Nonce/Salt 等加密参数）
        const globalHeader = new Uint8Array(GLOBAL_HEADER_SIZE);
        globalHeader.set(MagicNumber);
        const ghView = new DataView(globalHeader.buffer);
        ghView.setUint32(0x10, ModMetaProtocolVersion, true);
        let gFlags = GlobalFlags.None;
        if (hasEncrypted) gFlags |= GlobalFlags.HasEncryptedFiles;
        ghView.setUint32(0x14, gFlags, true);
        ghView.setUint32(0x18, hashSeed, true);
        if (hasEncrypted) {
            globalHeader.set(nonce, 0x1C);
            globalHeader.set(salt, 0x34);
        }

        // ── 第十步：构建 Block Offset Table (128 字节) ──
        // 记录各区块的字节偏移和长度，供读取器快速定位
        const blockOffsetTable = new Uint8Array(BLOCK_OFFSET_TABLE_SIZE);
        const botView = new DataView(blockOffsetTable.buffer);
        const offsets: BlockOffsets = {
            modMetaOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE,
            // length 字段记录真实有效字节数；offset 仍按 64B 对齐布局推进
            modMetaLength: modMetaRawBuf.length,
            bootJsonOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length,
            bootJsonLength: bootJsonRawBuf.length,
            hashIndexOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length,
            hashIndexLength: finalHashIndex.length,
            treeNodeOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length + finalHashIndex.length,
            treeNodeLength: finalTreeNodeArrayPadded.length,
            stringPoolOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length + finalHashIndex.length + finalTreeNodeArrayPadded.length,
            stringPoolLength: stringPoolPadded.length,
            fileStreamOffset: baseOffset,
            fileStreamLength: fileStreamBuffer.length
        };

        // 将偏移表写入二进制 (每对 offset+length 占 8 字节)
        botView.setUint32(0, offsets.modMetaOffset, true);
        botView.setUint32(4, offsets.modMetaLength, true);
        botView.setUint32(8, offsets.bootJsonOffset, true);
        botView.setUint32(12, offsets.bootJsonLength, true);
        botView.setUint32(16, offsets.hashIndexOffset, true);
        botView.setUint32(20, offsets.hashIndexLength, true);
        botView.setUint32(24, offsets.treeNodeOffset, true);
        botView.setUint32(28, offsets.treeNodeLength, true);
        botView.setUint32(32, offsets.stringPoolOffset, true);
        botView.setUint32(36, offsets.stringPoolLength, true);
        botView.setUint32(40, offsets.fileStreamOffset, true);
        botView.setUint32(44, offsets.fileStreamLength, true);

        // ── 最终组装：按顺序拼接所有区块 ──
        return this.concatUint8Arrays([
            globalHeader,          // 128B — 全局文件头
            blockOffsetTable,      // 128B — 主区块偏移表
            modMetaBuf,            // 64B 对齐 — 文件元数据信息区
            bootJsonBuf,           // 64B 对齐 — bootJson 引导信息区
            finalHashIndex,        // 64B 对齐 — Hash Index Array（O(1) 定位）
            finalTreeNodeArrayPadded, // 64B 对齐 — Tree Node Array（目录遍历）
            stringPoolPadded,      // 64B 对齐 — String Pool（局部文件名）
            fileStreamBuffer       // 64B 对齐 — 文件流区（Local Header + File Data）
        ]);
    }

    /** 拼接多个 Uint8Array 为单个连续数组 */
    private concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
        const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }

    /** 从叶子节点向上回溯，拼接出完整的文件路径 */
    private getFullPath(node: any): string {
        const parts = [];
        let curr = node;
        while (curr && curr.name !== "") {
            parts.unshift(curr.name);
            curr = curr.parent;
        }
        return parts.join('/');
    }

    /** 将大小向上对齐到 64 字节边界 */
    private alignTo64(size: number): number {
        return Math.ceil(size / 64) * 64;
    }

    /** 将数据填充到 64 字节对齐（尾部补 0x00） */
    private padToBlockSize(data: Uint8Array): Uint8Array {
        const target = this.alignTo64(data.length);
        if (target === data.length) return data;
        const padded = new Uint8Array(target);
        padded.set(data);
        return padded;
    }
}

/**
 * ModReaderV2 — V2 封包文件读取器
 *
 * 从二进制缓冲区中解析 JML V2 封包，提供：
 *   - getModMetaJson() / getBootJson() — 读取明文元数据
 *   - getTree() — 获取零拷贝目录树视图
 *   - findFile(path) — O(1) 全路径哈希定位文件
 *   - readFile(blockIdx) — 根据块编号读取文件数据
 *
 * 读取验证闭环（安全兜底）:
 *   1. 通过 xxHash64 查出 Block Index
 *   2. 跳转至该块读取 Local Header
 *   3. 强制验证 Local Header 中的明文路径与请求路径一致
 *   4. 验证通过后方可读取 File Data
 */
export class ModReaderV2 {
    private buffer: Uint8Array;
    private view: DataView;
    private offsets: BlockOffsets;
    private hashSeed: number;   // 从 Global Header 读取的完美哈希种子
    private tree: ZeroCopyTree; // 零拷贝目录树视图
    private xxhashApi: XXHashAPI;
    private decoder = new TextDecoder();

    private _nonce: Uint8Array;
    private _key?: Uint8Array;
    private _hasEncrypted: boolean;

    constructor(buffer: Uint8Array, xxhashApi: XXHashAPI, options?: { password?: string }) {
        this.buffer = buffer;
        this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.length);
        this.xxhashApi = xxhashApi;

        // 验证 Magic Number "JeremieModLoader"
        for (let i = 0; i < MagicNumber.length; i++) {
            if (this.view.getUint8(i) !== MagicNumber[i]) throw new Error("Invalid Magic Number");
        }

        // 从 Global Header 中读取 HashSeed (0x18~0x1B)
        this.hashSeed = this.view.getUint32(0x18, true);
        const globalFlags = this.view.getUint32(0x14, true);
        const hasEncrypted = (globalFlags & GlobalFlags.HasEncryptedFiles) !== 0;
        // 读取 Nonce 与 Salt（若存在）
        const nonce = new Uint8Array(crypto_stream_chacha20_NONCEBYTES);
        const salt = new Uint8Array(crypto_pwhash_SALTBYTES);
        nonce.set(this.buffer.subarray(0x1C, 0x1C + crypto_stream_chacha20_NONCEBYTES));
        salt.set(this.buffer.subarray(0x34, 0x34 + crypto_pwhash_SALTBYTES));
        this._nonce = nonce;
        this._hasEncrypted = hasEncrypted;
        this._key = undefined;
        if (hasEncrypted && options?.password) {
            // 同打包端一致的 KDF 参数
            // 注意：argon2-browser 为异步 API，Reader 构造函数为同步，这里将密钥推迟到 create()
        }

        // 从 Block Offset Table 中读取各区块的偏移与长度
        const botOff = GLOBAL_HEADER_SIZE;
        this.offsets = {
            modMetaOffset: this.view.getUint32(botOff, true),
            modMetaLength: this.view.getUint32(botOff + 4, true),
            bootJsonOffset: this.view.getUint32(botOff + 8, true),
            bootJsonLength: this.view.getUint32(botOff + 12, true),
            hashIndexOffset: this.view.getUint32(botOff + 16, true),
            hashIndexLength: this.view.getUint32(botOff + 20, true),
            treeNodeOffset: this.view.getUint32(botOff + 24, true),
            treeNodeLength: this.view.getUint32(botOff + 28, true),
            stringPoolOffset: this.view.getUint32(botOff + 32, true),
            stringPoolLength: this.view.getUint32(botOff + 36, true),
            fileStreamOffset: this.view.getUint32(botOff + 40, true),
            fileStreamLength: this.view.getUint32(botOff + 44, true),
        };

        // 构建零拷贝目录树视图（直接引用缓冲区子视图，无拷贝）
        this.tree = new ZeroCopyTree(
            this.buffer.subarray(this.offsets.treeNodeOffset, this.offsets.treeNodeOffset + this.offsets.treeNodeLength),
            this.buffer.subarray(this.offsets.stringPoolOffset, this.offsets.stringPoolOffset + this.offsets.stringPoolLength)
        );
    }

    public static async create(buffer: Uint8Array, options?: { password?: string }): Promise<ModReaderV2> {
        const api = await xxhash();
        const reader = new ModReaderV2(buffer, api, options);
        const hasEncrypted = (reader.view.getUint32(0x14, true) & GlobalFlags.HasEncryptedFiles) !== 0;
        if (hasEncrypted) {
            if (!options?.password) throw new Error('Encrypted pack requires password');
            const salt = reader.buffer.subarray(0x34, 0x34 + crypto_pwhash_SALTBYTES);
            const kdf = await argon2.hash({
                pass: options.password,
                salt,
                // time: 3,
                // mem: 1 << 16, // 64 MiB
                // parallelism: 1,
                hashLen: crypto_stream_chacha20_KEYBYTES,
                // type: (argon2 as any).ArgonType?.Argon2id ?? 2, // prefer Argon2id
            } as any);
            const hashBuf: ArrayBuffer | Uint8Array = (kdf as any).hash;
            (reader as any)._key = hashBuf instanceof Uint8Array ? hashBuf : new Uint8Array(hashBuf);
        }
        return reader;
    }

    /** 路径标准化：反斜杠转正斜杠，去除前导/后置斜杠 */
    private normalizePath(path: string): string {
        return path.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    }

    /** 读取 ModMeta JSON（明文，严格按偏移表中的真实长度切片） */
    public getModMetaJson(): string {
        const data = this.buffer.subarray(this.offsets.modMetaOffset, this.offsets.modMetaOffset + this.offsets.modMetaLength);
        return this.decoder.decode(data);
    }

    /** 读取 boot.json 引导信息（明文，严格按偏移表中的真实长度切片） */
    public getBootJson(): string {
        const data = this.buffer.subarray(this.offsets.bootJsonOffset, this.offsets.bootJsonOffset + this.offsets.bootJsonLength);
        return this.decoder.decode(data);
    }

    /** 获取零拷贝目录树视图 */
    public getTree(): ZeroCopyTree {
        return this.tree;
    }

    /**
     * O(1) 全路径哈希定位文件
     *
     * 流程：
     *   1. 对路径计算 xxHash64(path, HashSeed)
     *   2. 取模定位 Hash Index Array 中的槽位
     *   3. 比较哈希值是否匹配
     *   4. 跳转至 Local Header 验证明文路径（安全兜底，防止哈希碰撞）
     *
     * @param path 文件的完整路径（如 "textures/ui/icon.png"）
     * @returns 文件对应的 Block Index，未找到返回 null
     */
    public findFile(path: string): number | null {
        const normPath = this.normalizePath(path);
        const h = this.xxhashApi.h64(normPath, BigInt(this.hashSeed));
        const entryCount = this.offsets.hashIndexLength / 16;
        if (entryCount === 0) return null;

        const hashIdxBase = this.offsets.hashIndexOffset;
        const idx = Number(h % BigInt(entryCount));
        const entryOffset = hashIdxBase + idx * 16;
        // 读取 Hash Index 条目中的哈希值 (uint64)
        const entryHash = this.view.getBigUint64(entryOffset, true);

        if (entryHash === h) {
            // 哈希匹配，读取 block_index 并执行路径验证
            const blockIdx = this.view.getUint32(entryOffset + 8, true);
            if (this.verifyFile(blockIdx, normPath)) return blockIdx;
        }
        return null;
    }

    /**
     * 验证 Local Header 中的明文路径是否与期望路径一致
     * 防止"幽灵文件查寻碰撞"的安全兜底机制
     */
    private verifyFile(blockIdx: number, expectedPath: string): boolean {
        const offset = blockIdx * BlockSize;
        if (offset + 12 > this.buffer.length) return false;
        // 检查 Local Header 的 magic "FILE" (0x46 0x49 0x4C 0x45)
        if (this.buffer[offset] !== 0x46 || this.buffer[offset + 1] !== 0x49 ||
            this.buffer[offset + 2] !== 0x4C || this.buffer[offset + 3] !== 0x45) return false;

        // 读取 name_length 并比较完整路径
        const nameLen = this.view.getUint16(offset + 4, true);
        const path = this.decoder.decode(this.buffer.subarray(offset + 12, offset + 12 + nameLen));
        return this.normalizePath(path) === expectedPath;
    }

    /**
     * 根据 Block Index 读取文件数据
     *
     * 从 Local Header 中解析路径长度和真实数据长度，
     * 然后跳过 Local Header（对齐到 64 字节边界）读取 File Data。
     *
     * @param blockIdx 文件对应的 Local Header 块编号（由 findFile 或 Tree 获得）
     * @returns 文件原始数据的 Uint8Array 子视图（零拷贝）
     */
    public readFile(blockIdx: number): Uint8Array {
        const offset = blockIdx * BlockSize;
        const nameLen = this.view.getUint16(offset + 4, true);
        const realLen = this.view.getUint32(offset + 6, true);
        const flags = this.view.getUint16(offset + 10, true);
        const hashOffset = offset + 12 + nameLen;
        const storedHash = this.view.getBigUint64(hashOffset, true);
        // File Data 起始位置 = Local Header 起始 + 对齐后的头部大小（20 + nameLen）
        const dataStart = offset + this.alignTo64(20 + nameLen);
        if (dataStart + realLen > this.buffer.length) throw new Error(`Read out of bounds`);
        const slice = this.buffer.subarray(dataStart, dataStart + realLen);

        let plain = slice;
        const hasEncrypted = (this.view.getUint32(0x14, true) & GlobalFlags.HasEncryptedFiles) !== 0;
        if ((flags & LH_FLAG_ENCRYPTED) && hasEncrypted) {
            const key: Uint8Array | undefined = this._key;
            if (!key) throw new Error('Password not provided for encrypted pack');
            const nonce: Uint8Array = this._nonce;
            plain = xchacha20(key, nonce, slice, undefined, blockIdx);
        }
        const calcHash = this.xxhashApi.h64Raw(plain, BigInt(0));
        if (calcHash !== storedHash) throw new Error('File integrity check failed (xxHash64 mismatch)');
        return plain;
    }

    /** 将大小向上对齐到 64 字节边界 */
    private alignTo64(size: number): number {
        return Math.ceil(size / 64) * 64;
    }
}

/**
 * ModConverterV2 — V2 封包与 ZIP 格式的双向转换器
 *
 * 提供 ZIP → ModPack V2 和 ModPack V2 → ZIP 两个方向的转换，
 * 方便与现有基于 ZIP 的 Mod 生态互操作。
 */
export class ModConverterV2 {
    /**
     * 从 ZIP 文件创建 V2 封包
     *
     * @param zipData      ZIP 文件的二进制数据
     * @param modMetaJson  ModMeta JSON 字符串
     * @param bootJson     boot.json 引导信息
     * @returns V2 封包的二进制数据
     */
    public static async fromZip(zipData: Uint8Array, modMetaJson: string, bootJson: string): Promise<Uint8Array> {
        const zip = await JSZip.loadAsync(zipData);
        const files = new Map<string, Uint8Array>();
        const promises: Promise<void>[] = [];
        zip.forEach((path, file) => {
            if (!file.dir) {
                promises.push(file.async("uint8array").then(data => {
                    files.set(path, data);
                }));
            }
        });
        await Promise.all(promises);
        const packer = await ModPackerV2.create();
        return await packer.pack(files, modMetaJson, bootJson);
    }

    /**
     * 将 V2 封包转换回 ZIP 格式
     *
     * 通过 ModReaderV2 解析封包，遍历目录树提取所有文件，
     * 重新打包为标准 ZIP 格式。
     *
     * @param modPackData V2 封包的二进制数据
     * @returns ZIP 文件的二进制数据
     */
    public static async toZip(modPackData: Uint8Array): Promise<Uint8Array> {
        const reader = await ModReaderV2.create(modPackData);
        const zip = new JSZip();
        const tree = reader.getTree();
        const root = tree.buildJsObjectTree();

        // 递归遍历目录树，将所有文件添加到 ZIP
        const addNodeToZip = (node: JsFileNode, currentPath: string) => {
            const nodePath = currentPath ? `${currentPath}/${node.name}` : node.name;
            if (node.isFile) {
                if (node.blockIndex !== undefined) zip.file(nodePath, reader.readFile(node.blockIndex));
            } else if (node.children) {
                for (const childName in node.children) addNodeToZip(node.children[childName], nodePath);
            }
        };
        if (root.children) {
            for (const childName in root.children) addNodeToZip(root.children[childName], "");
        }
        // 单独写入 boot.json（从元数据区读取，非文件流区）
        zip.file("boot.json", reader.getBootJson());
        return await zip.generateAsync({type: "uint8array"});
    }
}
