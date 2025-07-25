import {} from 'lodash';
import {BSON} from 'bson';

import {
    ready,
    randombytes_buf,
    crypto_stream_xchacha20_xor_ic,
    crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES,
    to_hex,
    to_base64,
    from_hex,
    from_base64,
    randombytes_uniform,
    crypto_pwhash,
    crypto_pwhash_SALTBYTES,
    crypto_pwhash_ALG_DEFAULT,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
} from 'libsodium-wrappers-sumo';


export interface FileMeta {
    // begin block index
    b: number;
    // end block index
    e: number;
    // file length (byte)
    l: number;
}

export interface CryptoInfo {
    // xchacha20 nonce in base64 . if not crypted, it is empty string
    // if node crypted, the file ext is ( .modpack )
    // if crypted, the file ext is ( .modpack.crypt )
    Xchacha20NonceBase64: string;
    PwhashSaltBase64: string;
}

export const magicNumber = new Uint8Array([0x4A, 0x65, 0x72, 0x65, 0x6D, 0x69, 0x65, 0x4D, 0x6F, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72]);

export interface ModMeta {
    // magic number, 0x4A, 0x65, 0x72, 0x65, 0x6D, 0x69, 0x65, 0x4D, 0x6F, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72
    magicNumber: Uint8Array;
    // mod name
    name: string;
    // PAK file protocol version
    protocolVersion: string;
    // default: 64-byte . for xchacha20 fast lookup block
    blockSize: number;
    cryptoInfo?: CryptoInfo;
    // the boot.json file meta
    bootJsonFile: FileMeta;
    // <filepath , FileMeta>
    // dont forgot to verify the FileMeta not overlap when decompressing
    // and the filePath is relative path, not absolute path
    fileMeta: Record<string, FileMeta>;
}

function paddingToBlockSize(data: Uint8Array, blockSize: number): {
    blocks: number,
    dataLength: number,
    paddingLength: number,
    paddedData: Uint8Array,
    paddedDataLength: number,
    filePath?: string,
} {
    const paddingLength = blockSize - (data.length % blockSize);
    const blocks = Math.ceil(data.length / blockSize);
    if (paddingLength === blockSize) {
        return {
            blocks: blocks,
            dataLength: data.length,
            paddingLength: 0,
            paddedData: data, // No padding needed
            paddedDataLength: data.length,
        }
    }
    if (paddingLength < 0 || paddingLength > blockSize) {
        throw new Error(`Invalid padding length: ${paddingLength}. Data length: ${data.length}, Block size: ${blockSize}`);
    }
    const padding = new Uint8Array(paddingLength);
    for (let i = 0; i < paddingLength; i++) {
        padding[i] = randombytes_uniform(0xff); // Fill padding with random bytes
    }
    const paddedData = new Uint8Array(data.length + paddingLength);
    paddedData.set(data);
    paddedData.set(padding, data.length);
    return {
        blocks: blocks,
        dataLength: data.length,
        paddingLength: paddingLength,
        paddedData: paddedData,
        paddedDataLength: paddedData.length,
    };
}

export async function covertFromZipMod(
    modName: string,
    filePathList: string[],
    fileReaderFunc: (filePath: string) => Promise<Uint8Array | undefined>,
    password: string | undefined = undefined,
    bootFilePath: string = 'boot.json',
) {
    await ready;

    // filePathList duplicate check
    const filePathSet = new Set(filePathList);
    filePathSet.add(bootFilePath);
    if (filePathSet.size - 1 !== filePathList.length) {
        console.error('filePathList has duplicate entries', filePathList);
        throw new Error('filePathList has duplicate entries');
    }

    const blockSize = 64; // default block size

    let cryptoInfo: CryptoInfo | undefined;
    if (password) {
        cryptoInfo = {} as CryptoInfo;
        const xchacha20Nonce = randombytes_buf(crypto_stream_xchacha20_NONCEBYTES, 'uint8array');
        const xchacha20NonceBase64 = to_base64(xchacha20Nonce);
        cryptoInfo['Xchacha20NonceBase64'] = xchacha20NonceBase64;
        const pwhashSalt = randombytes_buf(crypto_pwhash_SALTBYTES, 'uint8array');
        const pwhashSaltBase64 = to_base64(pwhashSalt);
        cryptoInfo['PwhashSaltBase64'] = pwhashSaltBase64;
        // const xchacha20Key = crypto_pwhash(
        //     crypto_stream_xchacha20_KEYBYTES,
        //     password ?? '',
        //     pwhashSalt,
        //     crypto_pwhash_OPSLIMIT_INTERACTIVE,
        //     crypto_pwhash_MEMLIMIT_INTERACTIVE,
        //     crypto_pwhash_ALG_DEFAULT,
        //     'uint8array',
        // );
        // // example
        // crypto_stream_xchacha20_xor_ic(
        //     '',
        //     xchacha20Nonce,
        //     0,
        //     xchacha20Key,
        //     'uint8array',
        // );
    }

    const bootFile = await fileReaderFunc(bootFilePath);
    if (!bootFile) {
        console.error(`Boot file ${bootFilePath} not found`);
        throw new Error(`Boot file ${bootFilePath} not found`);
    }
    let bootJsonFile = paddingToBlockSize(
        bootFile,
        blockSize,
    );
    bootJsonFile['filePath'] = bootFilePath;

    const fileBlockList: ReturnType<typeof paddingToBlockSize>[] = [];
    for (const filePath of filePathList) {
        const fileData = await fileReaderFunc(filePath);
        if (!fileData) {
            console.error(`File ${filePath} not found`);
            throw new Error(`File ${filePath} not found`);
        }
        const fileBlock = paddingToBlockSize(
            fileData,
            blockSize,
        );
        fileBlock['filePath'] = filePath;
        fileBlockList.push(fileBlock);
    }

    const modMeta: ModMeta = {
        magicNumber: magicNumber,
        name: modName,
        protocolVersion: '1.0.0',
        blockSize: blockSize,
        cryptoInfo: cryptoInfo,
        bootJsonFile: {
            b: 0,
            e: bootJsonFile.blocks - 1,
            l: bootJsonFile.dataLength,
        },
        fileMeta: {},
    } satisfies ModMeta;

    const fileMetaList: FileMeta[] = [];
    let bockIndex = bootJsonFile.blocks;
    for (const fileBlock of fileBlockList) {
        const fileMeta: FileMeta = {
            b: bockIndex,
            e: bockIndex + fileBlock.blocks - 1,
            l: fileBlock.dataLength,
        };
        modMeta.fileMeta[fileBlock.filePath!] = fileMeta;
        fileMetaList.push(fileMeta);
        bockIndex += fileBlock.blocks;
    }

    const modMetaBuffer = BSON.serialize(modMeta);

    const magicNumberPadded = paddingToBlockSize(magicNumber, blockSize);
    const modMetaBufferPadded = paddingToBlockSize(modMetaBuffer, blockSize);

    // Calculate the total file length
    // magicNumber (16 bytes) + 8 bytes modMetaBuffer start pos + 8 bytes all file data start pos
    // + modMetaBuffer + (boot file data + all file data)
    const fileLength = magicNumberPadded.paddedDataLength + 8 + 8 + modMetaBufferPadded.paddedDataLength + fileBlockList.reduce((acc, block) => acc + block.paddedDataLength, 0);


    const modPackBuffer = new Uint8Array(fileLength);
    let offset = 0;
    modPackBuffer.set(magicNumberPadded.paddedData, offset);
    offset += magicNumberPadded.paddedDataLength;
    const dataView = new DataView(modPackBuffer.buffer);
    dataView.setBigUint64(offset, BigInt(magicNumberPadded.paddedDataLength + 8 + 8), true); // modMetaBuffer start pos
    offset += 8;
    dataView.setBigUint64(offset, BigInt(magicNumberPadded.paddedDataLength + 8 + 8 + modMetaBufferPadded.paddedDataLength), true); // all file data start pos
    offset += 8;
    modPackBuffer.set(modMetaBufferPadded.paddedData, offset);
    offset += modMetaBufferPadded.paddedDataLength;
    modPackBuffer.set(bootJsonFile.paddedData, offset);
    offset += bootJsonFile.paddedDataLength;
    for (const fileBlock of fileBlockList) {
        modPackBuffer.set(fileBlock.paddedData, offset);
        offset += fileBlock.paddedDataLength;
    }
    if (!cryptoInfo) {
        return {
            modMeta: modMeta,
            modPackBuffer: modPackBuffer,
            ext: cryptoInfo ? '.modpack.crypt' : '.modpack',
        };
    }

    // ==========================================================================================================
    // Encrypt the modPackBuffer with xchacha20 , only the file data part , block by block , inplace encryption

    const xchacha20Nonce: Uint8Array = from_base64(cryptoInfo.Xchacha20NonceBase64);
    if (xchacha20Nonce.length !== crypto_stream_xchacha20_NONCEBYTES) {
        console.error(`Invalid xchacha20 nonce length: ${xchacha20Nonce.length}, expected: ${crypto_stream_xchacha20_NONCEBYTES}`);
        throw new Error(`Invalid xchacha20 nonce length: ${xchacha20Nonce.length}, expected: ${crypto_stream_xchacha20_NONCEBYTES}`);
    }
    const pwhashSalt: Uint8Array = from_base64(cryptoInfo.PwhashSaltBase64);
    const xchacha20Key = crypto_pwhash(
        crypto_stream_xchacha20_KEYBYTES,
        password ?? '',
        pwhashSalt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT,
        'uint8array',
    );

    let blockPosIndex = 0;
    const blockIndexLast = bockIndex;
    const startPos = magicNumberPadded.paddedDataLength + 8 + 8 + modMetaBufferPadded.paddedDataLength;
    for (let blockIndex = 0; blockIndex < blockIndexLast; blockIndex++) {

        const blockStartPos = startPos + blockPosIndex * blockSize;
        const blockEndPos = blockStartPos + blockSize;
        const blockData = modPackBuffer.slice(blockStartPos, blockEndPos);
        if (blockData.length < blockSize) {
            // If the last block is not full
            // this will never happen
            console.warn(`Block data length is less than block size: ${blockData.length} < ${blockSize}`);
            throw new Error(`Block data length is less than block size: ${blockData.length} < ${blockSize}`);
        }
        const encryptedBlock = crypto_stream_xchacha20_xor_ic(
            blockData,
            xchacha20Nonce,
            blockIndex,
            xchacha20Key,
            'uint8array',
        );
        modPackBuffer.set(encryptedBlock, blockStartPos);
        blockPosIndex++;
    }

    return {
        modMeta: modMeta,
        modPackBuffer: modPackBuffer,
        ext: cryptoInfo ? '.modpack.crypt' : '.modpack',
    };

}
