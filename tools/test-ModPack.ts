import {join, basename} from 'path';
// import {promisify} from 'util';
import fs from 'fs/promises';
// import JsZip from 'jszip';
import {
    covertFromZipMod,
    ModPackFileReader,
} from '../src/ModPack';
import * as console from "node:console";

async function readFile(path: string): Promise<Uint8Array> {
    return fs.readFile(path, {
        flag: 'r',
    });
}

const filePathList = [
    '1.txt',
    '2.txt',
    '3.bin',

    '1/1.txt',
    '1/2.txt',

    '2/1.txt',
    '2/2.txt',

    '1/2/1.txt',
    '1/2/2.txt',
];

async function testMakeFile() {
    const modName = 'testMod';
    const fileRoot = 'tools/test-file';

    const out = await covertFromZipMod(
        modName,
        filePathList,
        async (fileName: string) => {
            const filePath = join(fileRoot, fileName);
            const d = await readFile(filePath);
            if (!d || d.length === 0) {
                console.error(`File ${filePath} is empty or does not exist.`);
                throw new Error(`File ${filePath} is empty or does not exist.`);
            }
            return d;
        },
        // '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
    );

    console.log('modMeta');
    console.log(out.ext);
    console.log(out.modMeta);
    await fs.writeFile(
        `${fileRoot}/${modName}${out.ext}`,
        out.modPackBuffer,
        {
            flag: 'w',
        },
    );

}

function isEqualByte(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

async function testReadFile() {
    const reader = new ModPackFileReader();
    const filePath = join(
        'tools/test-file',
        'testMod.modpack',
        // 'testMod.modpack.crypt',
    );
    const data = await readFile(filePath);
    if (!data || data.length === 0) {
        console.error(`File ${filePath} is empty or does not exist.`);
        throw new Error(`File ${filePath} is empty or does not exist.`);
    }
    // console.log('data', data.length);
    await reader.load(
        data,
        // '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
    );
    console.log('modMeta', reader.modMeta);

    const fileTree = await reader.getFileTree();
    console.log('fileTree', fileTree);

    const checkValid = await reader.checkValid();
    console.log('checkValid', checkValid);
    if (!checkValid) {
        console.error('Mod pack is not valid.');
        throw new Error('Mod pack is not valid.');
    }

    // compare the file list
    const fileList = reader.getFileList();
    console.log('fileList', fileList);
    if (fileList.length !== filePathList.length) {
        console.error(`File list length mismatch: expected ${filePathList.length}, got ${fileList.length}`);
        throw new Error(`File list length mismatch: expected ${filePathList.length}, got ${fileList.length}`);
    }
    for (const fileName of filePathList) {
        if (!fileList.includes(fileName)) {
            console.error(`File ${fileName} not found in the mod pack.`);
            throw new Error(`File ${fileName} not found in the mod pack.`);
        }
    }
    console.log('All files found in the mod pack.');
    // read the files
    for (const fileName of fileList) {
        const fileData = await reader.readFile(fileName);
        if (!fileData || fileData.length === 0) {
            console.error(`File ${fileName} is empty or does not exist in the mod pack.`);
            throw new Error(`File ${fileName} is empty or does not exist in the mod pack.`);
        }
        // compare data
        const originalFilePath = join('tools/test-file', fileName);
        const originalData = await readFile(originalFilePath);
        if (originalData.length !== fileData.length) {
            console.error(`File ${fileName} size mismatch: expected ${originalData.length}, got ${fileData.length}`);
            throw new Error(`File ${fileName} size mismatch: expected ${originalData.length}, got ${fileData.length}`);
        }
        if (!isEqualByte(originalData, fileData)) {
            console.error(`File ${fileName} content mismatch.`);
            console.log(originalData);
            console.log(fileData);
            throw new Error(`File ${fileName} content mismatch.`);
        }
        console.log(`File ${fileName} read successfully, size: ${fileData.length}`);
    }
    console.log('All files read successfully.');
}


// ;(testMakeFile().catch(console.error));
// ;(testReadFile().catch(console.error));

;(async () => {
    await testMakeFile();
    await testReadFile();
    console.log('Test completed successfully.');
})().catch(console.error);




