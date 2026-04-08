import { ModPackerV2, ModReaderV2, ModConverterV2 } from "../src/ModPackV2";
import xxhash from "xxhash-wasm";
import JSZip from "jszip";

async function test() {
    const api = await xxhash();
    const packer = new ModPackerV2(api);

    const files = new Map<string, Uint8Array>();
    files.set("a.txt", new TextEncoder().encode("Hello A"));
    files.set("sub/b.txt", new TextEncoder().encode("Hello B"));
    files.set("sub/inner/c.txt", new TextEncoder().encode("Hello C"));

    const modMeta = JSON.stringify({ name: "Test Mod", version: "1.0.0" });
    const bootJson = JSON.stringify({ entry: "a.txt" });

    console.log("Packing...");
    const packed = await packer.pack(files, modMeta, bootJson);
    console.log("Packed size:", packed.length);

    console.log("Reading...");
    const reader = new ModReaderV2(packed, api);
    
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
    const zipData = await ModConverterV2.toZip(packed);
    const zip = await JSZip.loadAsync(zipData);
    const bContent = await zip.file("sub/b.txt")?.async("string");
    if (bContent !== "Hello B") throw new Error("Zip content mismatch for sub/b.txt");

    console.log("Testing Converter (fromZip)...");
    const packedFromZip = await ModConverterV2.fromZip(zipData, modMeta, bootJson);
    const reader2 = new ModReaderV2(packedFromZip, api);
    
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
