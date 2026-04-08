import {
    BlockOffsets,
    BlockSize,
    GLOBAL_HEADER_SIZE,
    BLOCK_OFFSET_TABLE_SIZE,
    GlobalFlags,
    LocalHeaderMagic,
    MagicNumber,
    ModMetaProtocolVersion,
    TreeNodeFlags
} from "./ModMetaV2";
import xxhash from "xxhash-wasm";
import JSZip from "jszip";

// 用于表示 JS 内存 tree 对象的接口
export interface JsFileNode {
    name: string;
    isFile: boolean;
    size?: number;             // 仅文件有
    blockIndex?: number;       // 仅文件有
    children?: Record<string, JsFileNode>; // 仅目录有，使用 Map/Record 方便访问
}

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

    private readLocalName(nodeIndex: number): string {
        const offset = nodeIndex * 32;
        const nameOffset = this.treeData.getUint32(offset, true);
        const nameLen = this.treeData.getUint16(offset + 4, true);
        const buf = this.stringPool.subarray(nameOffset, nameOffset + nameLen);
        return this.decoder.decode(buf);
    }

    public readDirInPlace(dirNodeIndex: number = 0): string[] {
        const offset = dirNodeIndex * 32;
        const isDir = (this.treeData.getUint16(offset + 6, true) & 1) === 1;
        if (!isDir) throw new Error("Not a directory");

        const childStart = this.treeData.getUint32(offset + 12, true);
        const childCount = this.treeData.getUint32(offset + 16, true);

        const list = [];
        for (let i = 0; i < childCount; i++) {
            list.push(this.readLocalName(childStart + i));
        }
        return list;
    }

    public findChildInPlace(dirNodeIndex: number, targetName: string): number | null {
        const childStart = this.treeData.getUint32(dirNodeIndex * 32 + 12, true);
        const childCount = this.treeData.getUint32(dirNodeIndex * 32 + 16, true);

        let left = 0;
        let right = childCount - 1;

        while (left <= right) {
            const mid = (left + right) >> 1;
            const midIndex = childStart + mid;
            const midName = this.readLocalName(midIndex);

            if (midName === targetName) return midIndex;
            if (midName < targetName) left = mid + 1;
            else right = mid - 1;
        }
        return null;
    }

    public buildJsObjectTree(nodeIndex: number = 0): JsFileNode {
        const offset = nodeIndex * 32;
        const flags = this.treeData.getUint16(offset + 6, true);
        const isDir = (flags & 1) === 1;

        const node: JsFileNode = {
            name: this.readLocalName(nodeIndex),
            isFile: !isDir
        };

        const targetIndex = this.treeData.getUint32(offset + 12, true);
        const targetSize = this.treeData.getUint32(offset + 16, true);

        if (isDir) {
            node.children = {};
            for (let i = 0; i < targetSize; i++) {
                const childNodeIndex = targetIndex + i;
                const childObj = this.buildJsObjectTree(childNodeIndex);
                node.children[childObj.name] = childObj;
            }
        } else {
            node.blockIndex = targetIndex;
            node.size = targetSize;
        }

        return node;
    }
}

export class ModPackerV2 {
    private encoder = new TextEncoder();
    private xxhashApi: any;

    constructor(xxhashApi: any) {
        this.xxhashApi = xxhashApi;
    }

    public static async create(): Promise<ModPackerV2> {
        const api = await xxhash();
        return new ModPackerV2(api);
    }

    private normalizePath(path: string): string {
        return path.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    }

    public async pack(
        files: Map<string, Uint8Array>,
        modMetaJson: string,
        bootJson: string,
        options: { hashSeed?: number } = {}
    ): Promise<Uint8Array> {
        const normalizedFiles = new Map<string, Uint8Array>();
        for (const [path, data] of files) {
            const norm = this.normalizePath(path);
            if (norm === "boot.json") continue;
            normalizedFiles.set(norm, data);
        }
        normalizedFiles.set("boot.json", this.encoder.encode(bootJson));

        const sortedPaths = Array.from(normalizedFiles.keys()).sort();
        const root: any = { name: "", children: new Map(), isFile: false };
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

        const treeNodes: any[] = [];
        const stringPoolParts: Uint8Array[] = [];
        let currentStringOffset = 0;

        const processNode = (node: any, parent: any = null) => {
            const nodeIdx = treeNodes.length;
            treeNodes.push(node);
            node.index = nodeIdx;
            node.parent = parent;

            const nameBuf = this.encoder.encode(node.name);
            node.nameOffset = currentStringOffset;
            node.nameLength = nameBuf.length;
            stringPoolParts.push(nameBuf);
            currentStringOffset += nameBuf.length;

            if (!node.isFile) {
                const sortedChildren = Array.from(node.children.values())
                    .sort((a: any, b: any) => a.name.localeCompare(b.name));
                node.childStart = 0;
                node.childCount = sortedChildren.length;
                node.sortedChildren = sortedChildren;
            }
        };

        const queue: {node: any, parent: any}[] = [{node: root, parent: null}];
        let head = 0;
        while(head < queue.length) {
            const {node, parent} = queue[head++];
            processNode(node, parent);
            if (!node.isFile) {
                node.childStart = queue.length;
                for (const child of node.sortedChildren) {
                    queue.push({node: child, parent: node});
                }
            }
        }

        const stringPoolBuffer = this.concatUint8Arrays(stringPoolParts);
        const stringPoolPadded = this.padToBlockSize(new Uint8Array(stringPoolBuffer));

        const modMetaBuf = this.padToBlockSize(this.encoder.encode(modMetaJson));
        const bootJsonBuf = this.padToBlockSize(this.encoder.encode(bootJson));
        const treeNodeArraySize = this.alignTo64(treeNodes.length * 32);

        let hashSeed = options.hashSeed || Math.floor(Math.random() * 0xFFFFFFFF);
        const entryCount = this.alignTo64(sortedPaths.length * 16) / 16;
        let finalHashIndex = new Uint8Array(entryCount * 16);

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
                slots[slotIdx] = { h, path };
            }
            if (!collision) break;
            hashSeed = (hashSeed + 1) >>> 0;
        }

        const baseOffset = GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE +
                           modMetaBuf.length + bootJsonBuf.length +
                           finalHashIndex.length + treeNodeArraySize + stringPoolPadded.length;

        let currentAbsoluteOffset = baseOffset;
        const fileStreamChunks: Uint8Array[] = [];
        const fileEntries: { path: string, blockIndex: number, size: number }[] = [];

        for (const path of sortedPaths) {
            const data = normalizedFiles.get(path)!;
            const pathBuf = this.encoder.encode(path);
            const localHeaderSize = this.alignTo64(12 + pathBuf.length);

            // Block Index IS byteOffset / 64
            const blockIndex = currentAbsoluteOffset / BlockSize;
            fileEntries.push({ path, blockIndex, size: data.length });

            const lh = new Uint8Array(localHeaderSize);
            lh.set(LocalHeaderMagic);
            const lhView = new DataView(lh.buffer);
            lhView.setUint16(4, pathBuf.length, true);
            lhView.setUint32(6, data.length, true);
            lh.set(pathBuf, 12);
            fileStreamChunks.push(lh);

            fileStreamChunks.push(data);
            const dataPadding = (BlockSize - (data.length % BlockSize)) % BlockSize;
            if (dataPadding > 0) fileStreamChunks.push(new Uint8Array(dataPadding));
            currentAbsoluteOffset += localHeaderSize + data.length + dataPadding;
        }

        const fileStreamBuffer = this.concatUint8Arrays(fileStreamChunks);

        const hashIndexView = new DataView(finalHashIndex.buffer);
        for (const entry of fileEntries) {
            const h = this.xxhashApi.h64(entry.path, BigInt(hashSeed));
            const slotIdx = Number(h % BigInt(entryCount));
            const off = slotIdx * 16;
            hashIndexView.setBigUint64(off, h, true);
            hashIndexView.setUint32(off + 8, entry.blockIndex, true);
        }

        const finalTreeNodeArray = new Uint8Array(treeNodes.length * 32);
        const treeNodeView = new DataView(finalTreeNodeArray.buffer);
        for (let i = 0; i < treeNodes.length; i++) {
            const node = treeNodes[i];
            const offset = i * 32;
            treeNodeView.setUint32(offset, node.nameOffset, true);
            treeNodeView.setUint16(offset + 4, node.nameLength, true);
            treeNodeView.setUint16(offset + 6, node.isFile ? TreeNodeFlags.IsFile : TreeNodeFlags.IsDirectory, true);
            if (node.isFile) {
                const fullPath = this.getFullPath(node);
                const entry = fileEntries.find(e => e.path === fullPath);
                treeNodeView.setUint32(offset + 12, entry!.blockIndex, true);
                treeNodeView.setUint32(offset + 16, entry!.size, true);
            } else {
                treeNodeView.setUint32(offset + 12, node.childStart, true);
                treeNodeView.setUint32(offset + 16, node.childCount, true);
            }
        }

        // Padded to block size
        const finalTreeNodeArrayPadded = this.padToBlockSize(finalTreeNodeArray);

        const globalHeader = new Uint8Array(GLOBAL_HEADER_SIZE);
        globalHeader.set(MagicNumber);
        const ghView = new DataView(globalHeader.buffer);
        ghView.setUint32(0x10, ModMetaProtocolVersion, true);
        ghView.setUint32(0x14, GlobalFlags.None, true);
        ghView.setUint32(0x18, hashSeed, true);

        const blockOffsetTable = new Uint8Array(BLOCK_OFFSET_TABLE_SIZE);
        const botView = new DataView(blockOffsetTable.buffer);
        const offsets: BlockOffsets = {
            modMetaOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE,
            modMetaLength: modMetaBuf.length,
            bootJsonOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length,
            bootJsonLength: bootJsonBuf.length,
            hashIndexOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length,
            hashIndexLength: finalHashIndex.length,
            treeNodeOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length + finalHashIndex.length,
            treeNodeLength: finalTreeNodeArrayPadded.length,
            stringPoolOffset: GLOBAL_HEADER_SIZE + BLOCK_OFFSET_TABLE_SIZE + modMetaBuf.length + bootJsonBuf.length + finalHashIndex.length + finalTreeNodeArrayPadded.length,
            stringPoolLength: stringPoolPadded.length,
            fileStreamOffset: baseOffset,
            fileStreamLength: fileStreamBuffer.length
        };

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

        return this.concatUint8Arrays([
            globalHeader,
            blockOffsetTable,
            modMetaBuf,
            bootJsonBuf,
            finalHashIndex,
            finalTreeNodeArrayPadded,
            stringPoolPadded,
            fileStreamBuffer
        ]);
    }

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

    private getFullPath(node: any): string {
        const parts = [];
        let curr = node;
        while (curr && curr.name !== "") {
            parts.unshift(curr.name);
            curr = curr.parent;
        }
        return parts.join('/');
    }

    private alignTo64(size: number): number {
        return Math.ceil(size / 64) * 64;
    }

    private padToBlockSize(data: Uint8Array): Uint8Array {
        const target = this.alignTo64(data.length);
        if (target === data.length) return data;
        const padded = new Uint8Array(target);
        padded.set(data);
        return padded;
    }
}

export class ModReaderV2 {
    private buffer: Uint8Array;
    private view: DataView;
    private offsets: BlockOffsets;
    private hashSeed: number;
    private tree: ZeroCopyTree;
    private xxhashApi: any;
    private decoder = new TextDecoder();

    constructor(buffer: Uint8Array, xxhashApi: any) {
        this.buffer = buffer;
        this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.length);
        this.xxhashApi = xxhashApi;

        for (let i = 0; i < MagicNumber.length; i++) {
            if (this.view.getUint8(i) !== MagicNumber[i]) throw new Error("Invalid Magic Number");
        }

        this.hashSeed = this.view.getUint32(0x18, true);
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

        this.tree = new ZeroCopyTree(
            this.buffer.subarray(this.offsets.treeNodeOffset, this.offsets.treeNodeOffset + this.offsets.treeNodeLength),
            this.buffer.subarray(this.offsets.stringPoolOffset, this.offsets.stringPoolOffset + this.offsets.stringPoolLength)
        );
    }

    public static async create(buffer: Uint8Array): Promise<ModReaderV2> {
        const api = await xxhash();
        return new ModReaderV2(buffer, api);
    }

    private normalizePath(path: string): string {
        return path.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    }

    public getModMetaJson(): string {
        const data = this.buffer.subarray(this.offsets.modMetaOffset, this.offsets.modMetaOffset + this.offsets.modMetaLength);
        let end = data.indexOf(0);
        return this.decoder.decode(end === -1 ? data : data.subarray(0, end));
    }

    public getBootJson(): string {
        const data = this.buffer.subarray(this.offsets.bootJsonOffset, this.offsets.bootJsonOffset + this.offsets.bootJsonLength);
        let end = data.indexOf(0);
        return this.decoder.decode(end === -1 ? data : data.subarray(0, end));
    }

    public getTree(): ZeroCopyTree {
        return this.tree;
    }

    public findFile(path: string): number | null {
        const normPath = this.normalizePath(path);
        const h = this.xxhashApi.h64(normPath, BigInt(this.hashSeed));
        const entryCount = this.offsets.hashIndexLength / 16;
        if (entryCount === 0) return null;

        const hashIdxBase = this.offsets.hashIndexOffset;
        const idx = Number(h % BigInt(entryCount));
        const entryOffset = hashIdxBase + idx * 16;
        const entryHash = this.view.getBigUint64(entryOffset, true);

        if (entryHash === h) {
            const blockIdx = this.view.getUint32(entryOffset + 8, true);
            if (this.verifyFile(blockIdx, normPath)) return blockIdx;
        }
        return null;
    }

    private verifyFile(blockIdx: number, expectedPath: string): boolean {
        const offset = blockIdx * BlockSize;
        if (offset + 12 > this.buffer.length) return false;
        if (this.buffer[offset] !== 0x46 || this.buffer[offset+1] !== 0x49 ||
            this.buffer[offset+2] !== 0x4C || this.buffer[offset+3] !== 0x45) return false;

        const nameLen = this.view.getUint16(offset + 4, true);
        const path = this.decoder.decode(this.buffer.subarray(offset + 12, offset + 12 + nameLen));
        return this.normalizePath(path) === expectedPath;
    }

    public readFile(blockIdx: number): Uint8Array {
        const offset = blockIdx * BlockSize;
        const nameLen = this.view.getUint16(offset + 4, true);
        const realLen = this.view.getUint32(offset + 6, true);
        const dataStart = offset + this.alignTo64(12 + nameLen);
        if (dataStart + realLen > this.buffer.length) throw new Error(`Read out of bounds`);
        return this.buffer.subarray(dataStart, dataStart + realLen);
    }

    private alignTo64(size: number): number {
        return Math.ceil(size / 64) * 64;
    }
}

export class ModConverterV2 {
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

    public static async toZip(modPackData: Uint8Array): Promise<Uint8Array> {
        const reader = await ModReaderV2.create(modPackData);
        const zip = new JSZip();
        const tree = reader.getTree();
        const root = tree.buildJsObjectTree();
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
        zip.file("boot.json", reader.getBootJson());
        return await zip.generateAsync({ type: "uint8array" });
    }
}
