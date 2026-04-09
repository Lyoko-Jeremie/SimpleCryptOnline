import {ModPackerV2, ModReaderV2, ModConverterV2} from "../src/ModPackV2";
import xxhash from "xxhash-wasm";
import JSZip from "jszip";
import fs from "fs";
import {GLOBAL_HEADER_SIZE} from "../src/ModMetaV2";

async function test() {
    const api = await xxhash();
    const packer = new ModPackerV2(api);
    const encoder = new TextEncoder();

    const files = new Map<string, Uint8Array>();
    files.set("a.txt", new TextEncoder().encode("Hello A"));
    files.set("sub/b.txt", new TextEncoder().encode("Hello B"));
    files.set("sub/inner/c.txt", new TextEncoder().encode("Hello C"));

    const modMeta = `{"name":"Test Mod","version":"1.0.0"}\u0000META_TAIL`;
    const bootJson = `{"entry":"a.txt"}\u0000BOOT_TAIL`;

    console.log("Packing...");
    const packed = await packer.pack(files, modMeta, bootJson, {password: '123'});
    console.log("Packed size:", packed.length);

    await fs.promises.writeFile('test-ModPackV2-packed.modpack', packed);

    console.log("Reading...");
    const reader = await ModReaderV2.create(packed, {password: '123', xxhashApi: api});

    // 验证 BlockOffsetTable 中这两个 length 是真实长度，不是 64B 对齐长度
    const view = new DataView(packed.buffer, packed.byteOffset, packed.length);
    const modMetaLengthInTable = view.getUint32(GLOBAL_HEADER_SIZE + 4, true);
    const bootJsonLengthInTable = view.getUint32(GLOBAL_HEADER_SIZE + 12, true);
    if (modMetaLengthInTable !== encoder.encode(modMeta).length) {
        throw new Error(`modMetaLength mismatch: ${modMetaLengthInTable}`);
    }
    if (bootJsonLengthInTable !== encoder.encode(bootJson).length) {
        throw new Error(`bootJsonLength mismatch: ${bootJsonLengthInTable}`);
    }

    // 读取时必须严格按 length 解码，不能用 0x00 截断
    if (reader.getModMetaJson() !== modMeta) throw new Error("modMeta read mismatch");
    if (reader.getBootJson() !== bootJson) throw new Error("bootJson read mismatch");

    const blockIdxA = reader.findFile("a.txt");
    if (blockIdxA === null) throw new Error("a.txt not found");
    const contentA = new TextDecoder().decode(reader.readFile(blockIdxA));
    if (contentA !== "Hello A") throw new Error("Content mismatch for a.txt");

    const blockIdxC = reader.findFile("sub/inner/c.txt");
    if (blockIdxC === null) throw new Error("sub/inner/c.txt not found");
    const contentC = new TextDecoder().decode(reader.readFile(blockIdxC));
    if (contentC !== "Hello C") throw new Error("Content mismatch for sub/inner/c.txt");

    console.log("Testing Tree...");
    const tree = reader.getTree();
    const subIdx = tree.findChildInPlace(0, "sub");
    if (subIdx === null) throw new Error("sub dir not found in tree");
    const subChildren = tree.readDirInPlace(subIdx);
    if (!subChildren.includes("b.txt") || !subChildren.includes("inner")) throw new Error("sub children mismatch");

    console.log("Testing Converter (toZip)...");
    const zipData = await ModConverterV2.toZip(packed, {password: '123', xxhashApi: api});
    const zip = await JSZip.loadAsync(zipData);
    const bContent = await zip.file("sub/b.txt")?.async("string");
    if (bContent !== "Hello B") throw new Error("Zip content mismatch for sub/b.txt");

    console.log("Testing Converter (fromZip)...");
    const packedFromZip = await ModConverterV2.fromZip(zipData, modMeta, bootJson);
    const reader2 = await ModReaderV2.create(packedFromZip, {password: '123', xxhashApi: api});

    const blockIdxB = reader2.findFile("sub/b.txt");
    if (blockIdxB === null) {
        // Find by tree if findFile fails
        const root = reader2.getTree().buildJsObjectTree();
        console.log("Fallback search in tree...");
        const sub = root.children?.["sub"];
        const b = sub?.children?.["b.txt"];
        if (b && b.blockIndex !== undefined) {
            console.log("Found b.txt in tree at block", b.blockIndex);
            const content = new TextDecoder().decode(reader2.readFile(b.blockIndex));
            console.log("Content:", content);
        }
        throw new Error("sub/b.txt not found via hash index after zip conversion");
    }

    if (new TextDecoder().decode(reader2.readFile(blockIdxB)) !== "Hello B") {
        throw new Error("b.txt content mismatch after zip conversion");
    }

    console.log("All tests passed!");
}

test().catch(err => {
    console.error("Test failed:", err);
    process.exit(1);
});
