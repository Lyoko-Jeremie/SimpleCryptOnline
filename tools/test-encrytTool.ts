import {isNil, isString} from 'lodash';
import {
    ready,
    to_hex,
    to_base64,
    crypto_stream_xchacha20_keygen,
} from 'libsodium-wrappers-sumo';

import {readFile, writeFile, unlink} from 'fs';
import {join, basename} from 'path';
import {promisify} from 'util';
import {exit} from 'process';
import {
    generateNewSalt,
    calcKeyFromPassword,
    encryptFile,
    decryptFile,
    decryptXChaCha20Key,
    encryptXChaCha20Key, calcKeyFromPasswordBrowser,
} from "../src_mod/src/CryptoTool";
import JSON5 from "json5";
// @ts-ignore
import xxHash from 'xxhash-wasm';
import * as console from "node:console";
import * as child_process from "node:child_process";

function isEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
    if (arr1.length !== arr2.length) {
        return false;
    }

    return arr1.every((value, index) => value === arr2[index]);
}

async function encryptModZipFile(p: string, password: string) {
    await ready;
    const xxhash = await xxHash();

    const f = await promisify(readFile)(p);
    console.log('f', f.length);
    const hash = xxhash.h64Raw(f);
    console.log('hash', hash);

    const saltPwd = await generateNewSalt();
    console.log('saltPwd', saltPwd.length);
    console.log('saltPwd_hex', to_hex(saltPwd));
    console.log('saltPwd_base64', to_base64(saltPwd));
    const keyAdae = await calcKeyFromPassword(password, saltPwd);
    console.log('keyAdae', keyAdae.length);
    console.log('keyAdae_hex', to_hex(keyAdae));
    console.log('keyAdae_base64', to_base64(keyAdae));

    const xChaCha20Key = await encryptXChaCha20Key(keyAdae);
    // in-place crypt
    const fileRef = await encryptFile(f, xChaCha20Key.keyXChaCha20, xChaCha20Key.nonceXChaCha20);

    console.log('nonceAdae', xChaCha20Key.nonceAdae.length);
    console.log('nonceAdae_hex', to_hex(xChaCha20Key.nonceAdae));
    console.log('nonceAdae_base64', to_base64(xChaCha20Key.nonceAdae));
    console.log('nonceXChaCha20', xChaCha20Key.nonceXChaCha20.length);
    console.log('nonceXChaCha20_hex', to_hex(xChaCha20Key.nonceXChaCha20));
    console.log('nonceXChaCha20_base64', to_base64(xChaCha20Key.nonceXChaCha20));
    console.log('ciphertextXChaCha20', xChaCha20Key.ciphertextKeyXChaCha20.length);
    console.log('ciphertextXChaCha20_hex', to_hex(xChaCha20Key.ciphertextKeyXChaCha20));
    console.log('ciphertextXChaCha20_base64', to_base64(xChaCha20Key.ciphertextKeyXChaCha20));

    const R: {
        cryptFile: string,
        ciphertextKeyXChaCha20: string,
        nonceXChaCha20: string,
        nonceAdae: string,
        saltPwd: string,
    } = {} as any;

    R.cryptFile = `${basename(p)}.cryptFile`;
    R.ciphertextKeyXChaCha20 = `${basename(p)}.ciphertextKeyXChaCha20`;
    R.nonceXChaCha20 = `${basename(p)}.nonceXChaCha20`;
    R.nonceAdae = `${basename(p)}.nonceAdae`;
    R.saltPwd = `${basename(p)}.saltPwd`;
    await promisify(writeFile)(R.cryptFile, fileRef, {encoding: 'binary'});
    await promisify(writeFile)(R.ciphertextKeyXChaCha20, xChaCha20Key.ciphertextKeyXChaCha20, {encoding: 'binary'});
    await promisify(writeFile)(R.nonceXChaCha20, xChaCha20Key.nonceXChaCha20, {encoding: 'binary'});
    await promisify(writeFile)(R.nonceAdae, xChaCha20Key.nonceAdae, {encoding: 'binary'});
    await promisify(writeFile)(R.saltPwd, saltPwd, {encoding: 'binary'});

    // ---------------------------

    const kk = await calcKeyFromPasswordBrowser(password, saltPwd);
    const kkXc = await decryptXChaCha20Key(
        xChaCha20Key.ciphertextKeyXChaCha20,
        xChaCha20Key.nonceAdae,
        xChaCha20Key.nonceXChaCha20,
        kk,
    )
    const decrypted = await decryptFile(
        fileRef,
        kkXc,
        xChaCha20Key.nonceXChaCha20,
    );
    console.log('decrypted', decrypted.length);
    const hashD = xxhash.h64Raw(decrypted);
    console.log('hashD', hashD);
    console.log('hash === hashD', hash === hashD);

    return R;
}

async function runScript(scriptPath: string, args: string[]) {
    return new Promise((resolve, reject) => {

        // keep track of whether callback has been invoked to prevent multiple invocations
        let invoked = false;

        const process = child_process.spawn('node', [scriptPath].concat(args));

        process.stdout.on('data', function (data) {
            console.log(data.toString());
        });
        process.stderr.on('data', function (data) {
            console.error(data.toString());
        });

        // listen for errors as they may prevent the exit event from firing
        process.on('error', function (err) {
            if (invoked) return;
            invoked = true;
            reject(err);
        });

        // execute the callback once the process has finished running
        process.on('close', function (code) {
            if (invoked) return;
            invoked = true;
            resolve(code);
        });

    });
}

;(async () => {

    console.log('process.argv.length', process.argv.length);
    console.log('process.argv', process.argv);
    const packModZipJsFilePath = process.argv[2];
    const configJsonFilePath = process.argv[3];
    const bootTemplateJsonPath = process.argv[4];
    const modPath = process.argv[5];
    console.log('packModZipJsFilePath', packModZipJsFilePath);
    console.log('configJsonFilePath', configJsonFilePath);
    console.log('bootTemplateJsonPath', bootTemplateJsonPath);
    console.log('modPath', modPath);
    if (!configJsonFilePath) {
        console.error('no configJsonFilePath');
        process.exit(1);
        return;
    }
    if (!bootTemplateJsonPath) {
        console.error('no bootTemplateJsonPath');
        process.exit(1);
        return;
    }
    if (!modPath) {
        console.error('no modPath');
        process.exit(1);
        return;
    }

    const configJsonF = await promisify(readFile)(configJsonFilePath, {encoding: 'utf-8'});

    const configJson: {
        modName: string,
        password: string,
        passwordHintFile?: string,
    } = JSON5.parse(configJsonF);

    if (!(
        isString(configJson.password)
        && isString(configJson.modName)
        && (isNil(configJson.passwordHintFile) ? true : isString(configJson.passwordHintFile))
    )) {
        console.error('configJson invalid');
        process.exit(1);
        return;
    }

    const rEncrypt = await encryptModZipFile(modPath, configJson.password);

    // const bootTemplateJsonPath = 'bootTemplate.json';
    const bootTemplateJsonF = await promisify(readFile)(bootTemplateJsonPath, {encoding: 'utf-8'});
    const bootTemplateJson = JSON5.parse(bootTemplateJsonF);

    bootTemplateJson.name = configJson.modName;
    bootTemplateJson.additionBinaryFile = [
        rEncrypt.cryptFile,
        rEncrypt.saltPwd,
        rEncrypt.nonceAdae,
        rEncrypt.nonceXChaCha20,
        rEncrypt.ciphertextKeyXChaCha20,
    ];

    const passwordHintFilePath = 'passwordHintFile.txt';
    if (isString(configJson.passwordHintFile)) {
        await promisify(writeFile)(
            passwordHintFilePath,
            await promisify(readFile)(configJson.passwordHintFile, {encoding: 'utf-8'}),
            {encoding: 'utf-8'});
        if (!(bootTemplateJson.additionFile as string[]).find(T => T === passwordHintFilePath)) {
            (bootTemplateJson.additionFile as string[]).push(passwordHintFilePath);
        }
    } else {
        (bootTemplateJson.additionFile as string[]) = (bootTemplateJson.additionFile as string[]).filter(T => T !== passwordHintFilePath);
    }

    await promisify(writeFile)('boot.json', JSON5.stringify(bootTemplateJson, undefined, 2), {encoding: 'utf-8'});

    const rCode = await runScript(packModZipJsFilePath, ['boot.json']);

    if (rCode !== 0) {
        console.log('packModZip error', rCode);
        return;
    }

    console.log('clean temp file...');
    await promisify(unlink)('boot.json');
    await promisify(unlink)(rEncrypt.cryptFile);
    await promisify(unlink)(rEncrypt.saltPwd);
    await promisify(unlink)(rEncrypt.nonceAdae);
    await promisify(unlink)(rEncrypt.ciphertextKeyXChaCha20);
    await promisify(unlink)(rEncrypt.nonceXChaCha20);
    await promisify(unlink)(passwordHintFilePath);

    console.log('=== Congratulation! EncryptMod done! Everything is ok. ===');
})().catch(E => {
    console.error(E);
    exit(-1);
});
