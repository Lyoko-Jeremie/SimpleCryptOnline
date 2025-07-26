import {join, basename} from 'path';
// import {promisify} from 'util';
import fs from 'fs/promises';
import JsZip from 'jszip';
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

async function testZipFile2ModPack(zipFilePath: string) {
    const zipFileData = await fs.readFile(zipFilePath);
    const zip = await JsZip.loadAsync(zipFileData);
    const getFileFromZip = async (fileName: string): Promise<Uint8Array> => {
        const file = zip.file(fileName);
        if (!file) {
            console.error(`File ${fileName} not found in the zip.`);
            throw new Error(`File ${fileName} not found in the zip.`);
        }
        const data = await file.async('uint8array');
        if (!data) {
            console.error(`File ${fileName} is empty or does not exist in the zip.`);
            throw new Error(`File ${fileName} is empty or does not exist in the zip.`);
        }
        return data;
    }
    const bootFile = await zip.file('boot.json')?.async('string');
    if (!bootFile) {
        console.error('boot.json not found in the zip.');
        throw new Error('boot.json not found in the zip.');
    }
    const modName = JSON.parse(bootFile).name;
    if (!modName) {
        console.error('modName not found in boot.json.');
        throw new Error('modName not found in boot.json.');
    }
    // get all file list from zip
    const fileList = new Set(Object.keys(zip.files));
    fileList.delete('boot.json'); // remove boot.json from file list
    for (const fileName of fileList) {
        const f = zip.file(fileName);
        if (!f) {
            fileList.delete(fileName);
            continue;
        }
        if (f.dir) {
            // if the file is a directory, remove it from the file list
            fileList.delete(fileName);
            continue;
        }
    }
    if (fileList.size === 0) {
        console.error('No files found in the zip.');
        throw new Error('No files found in the zip.');
    }
    console.log(`Found ${fileList.size} files in the zip.`);
    // console.log(await zip.file('img/'));
    // console.log([...fileList].map(T => zip.file(T)));
    const out = await covertFromZipMod(
        modName,
        [...fileList],
        getFileFromZip,
        // '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
    );

    console.log('modMeta');
    console.log(out.ext);
    console.log(out.modMeta);
    await fs.writeFile(
        `${'.'}/${modName}${out.ext}`,
        out.modPackBuffer,
        {
            flag: 'w',
        },
    );
}

async function testModPack2ZipFile(modPackFilePath: string) {
    const modPackData = await fs.readFile(modPackFilePath);
    const reader = new ModPackFileReader();
    await reader.load(
        modPackData,
        // '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
    );
    console.log('modMeta', reader.modMetaInfo);

    const fileTree = await reader.getFileTree();
    console.log('fileTree', fileTree);

    const checkValid = await reader.checkValid();
    console.log('checkValid', checkValid);
    if (!checkValid) {
        console.error('Mod pack is not valid.');
        throw new Error('Mod pack is not valid.');
    }

    const fileList = reader.getFileList();

    const zip = new JsZip();
    zip.file('boot.json', JSON.stringify(reader.modMetaInfo, null, 2));
    for (const fileName of fileList) {
        const fileData = await reader.readFile(fileName);
        if (!fileData) {
            console.error(`File ${fileName} is empty or does not exist in the mod pack.`);
            throw new Error(`File ${fileName} is empty or does not exist in the mod pack.`);
        }
        zip.file(fileName, fileData);
    }
    const zipData = await zip.generateAsync({
        type: 'uint8array',
        compression: 'DEFLATE',
        compressionOptions: {
            level: 9, // Maximum compression level
        },
    });
    const zipFileName = basename(modPackFilePath, '.modpack') + '.mod.zip';
    await fs.writeFile(zipFileName, zipData, {
        flag: 'w',
    });
    console.log(`Mod pack converted to zip file: ${zipFileName}`);
    return zipFileName;

}

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
        '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
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
        // 'testMod.modpack',
        'testMod.modpack.crypt',
    );
    const data = await readFile(filePath);
    if (!data || data.length === 0) {
        console.error(`File ${filePath} is empty or does not exist.`);
        throw new Error(`File ${filePath} is empty or does not exist.`);
    }
    // console.log('data', data.length);
    await reader.load(
        data,
        '123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz123456789abcdefghijklmnopqrstuvwxyz',
    );
    console.log('modMeta', reader.modMetaInfo);

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

// ;(async () => {
//     await testMakeFile();
//     await testReadFile();
//     console.log('Test completed successfully.');
// })().catch(console.error);


// ;(testZipFile2ModPack('tools/GameOriginalImagePack.mod.zip').catch(console.error));
// ;(testModPack2ZipFile('GameOriginalImagePack.modpack.crypt').catch(console.error));
// ;(testModPack2ZipFile('GameOriginalImagePack.modpack').catch(console.error));


