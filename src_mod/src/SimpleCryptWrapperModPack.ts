import type {LogWrapper} from "../../../../dist-BeforeSC2/ModLoadController";
import type {SC2DataManager} from "../../../../dist-BeforeSC2/SC2DataManager";
import type {ModUtils} from "../../../../dist-BeforeSC2/Utils";
import type {JSZipLikeReadOnlyInterface} from "../../../../dist-BeforeSC2/JSZipLikeReadOnlyInterface";
import type {ModPackFileReaderJsZipAdaptor} from "../../../../dist-BeforeSC2/ModPack/ModPackJsZipAdaptor";
import {isModPackFileReaderJsZipAdaptor} from "../../../../dist-BeforeSC2/JSZipLikeReadOnlyInterface";
import {isString} from 'lodash';
import {ready} from 'libsodium-wrappers';
import {calcKeyFromPasswordBrowser, decryptFile, decryptXChaCha20Key} from './CryptoTool';
import {getStringTable} from "./GUI_StringTable/StringTable";
import {ISimpleCryptWrapper} from "./ISimpleCryptWrapper";
import {setRef} from "./CalcRef";

const ST = getStringTable();

export interface CryptDataItem {
    cryptFile: string;
    ciphertextKeyXChaCha20: string;
    nonceXChaCha20: string;
    nonceAdae: string;
    saltPwd: string;
}

const PasswordHintFile = 'passwordHintFile.txt';

export class SimpleCryptWrapperModPack implements ISimpleCryptWrapper {
    private logger: LogWrapper;

    private readonly ModName: string = '';

    private readonly infoCreateOk: boolean = false;

    constructor(
        public gSC2DataManager: SC2DataManager,
        public gModUtils: ModUtils,
    ) {
        this.logger = gModUtils.getLogger();
        if (gModUtils?.getSemVerTools && gModUtils.getSemVerTools()) {
            const semVer = gModUtils.getSemVerTools();
            if (semVer.satisfies(semVer.parseVersion(gModUtils.version).version, semVer.parseRange('>=2.5.1'))) {

                // do init
                const ModName = gModUtils.getNowRunningModName();
                if (isString(ModName)) {

                    this.ModName = ModName;
                    this.infoCreateOk = true;

                    setRef(ModName, this);

                    return;
                } else {
                    this.logger.error(`[SimpleCryptWrapperModPack] constructor failed, ModName is not string`);
                    return;
                }
            } else {
                this.logger.error(`[SimpleCryptWrapperModPack] constructor failed, ModLoader version not match. need >=2.5.1`);
            }
        } else {
            this.logger.error(`[SimpleCryptWrapperModPack] constructor failed, ModLoader version not match. no getSemVerTools.`);
        }
        return;
    }

    async decrypt() {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call decrypt(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call decrypt(), constructor not completed`);
        }
        try {
            console.log(`[${this.ModName}] decrypt`);
            this.logger.log(`[${this.ModName}] decrypt`);
            await ready;
            const mod = this.gSC2DataManager.getModLoader().getModByNameOne(this.ModName);
            if (!mod) {
                console.error(`[${this.ModName}] cannot find inner Mod , maybe the package is broken`);
                this.logger.error(`[${this.ModName}] cannot find inner Mod , maybe the package is broken`);
                return;
            }

            let passwordHint: string | undefined = undefined;
            if (mod.mod.bootJson.additionFile.find(T => T === PasswordHintFile)) {
                passwordHint = await mod.zip.zip.file(PasswordHintFile)?.async('string');
            }

            const cdi = new Map<string, CryptDataItem>();
            mod.mod.bootJson.additionBinaryFile?.forEach((T) => {
                let fileName = '';
                let typeName: keyof CryptDataItem;
                if (T.endsWith('.cryptFile')) {
                    fileName = T.slice(0, -10);
                    typeName = 'cryptFile';
                } else if (T.endsWith('.ciphertextKeyXChaCha20')) {
                    fileName = T.slice(0, -23);
                    typeName = 'ciphertextKeyXChaCha20';
                } else if (T.endsWith('.nonceXChaCha20')) {
                    fileName = T.slice(0, -15);
                    typeName = 'nonceXChaCha20';
                } else if (T.endsWith('.nonceAdae')) {
                    fileName = T.slice(0, -10);
                    typeName = 'nonceAdae';
                } else if (T.endsWith('.saltPwd')) {
                    fileName = T.slice(0, -8);
                    typeName = 'saltPwd';
                } else {
                    console.warn(`[${this.ModName}] Unknown file type`, T);
                    this.logger.warn(`[${this.ModName}] Unknown file type [${T}]`);
                    return;
                }
                if (!cdi.has(fileName)) {
                    cdi.set(fileName, {} as CryptDataItem);
                }
                const nn = cdi.get(fileName)!;
                nn[typeName] = T;
            });
            for (const nn of cdi) {
                if (!(nn[1].ciphertextKeyXChaCha20 && nn[1].nonceXChaCha20 && nn[1].nonceAdae && nn[1].saltPwd && nn[1].cryptFile)) {
                    console.warn(`[${this.ModName}] Missing file`, [nn]);
                    this.logger.warn(`[${this.ModName}] Missing file [${nn[0]}]`);
                    continue;
                }
                const pack: JSZipLikeReadOnlyInterface = mod.zip.zip;
                if (!isModPackFileReaderJsZipAdaptor(pack)) {
                    console.warn(`[${this.ModName}] pack is not ModPackFileReaderJsZipAdaptor`, [nn]);
                    this.logger.warn(`[${this.ModName}] pack is not ModPackFileReaderJsZipAdaptor [${nn[0]}]`);
                    continue;
                }
                const modpack: ModPackFileReaderJsZipAdaptor = pack;
                const ciphertextKeyXChaCha20 = await modpack.readFile(nn[1].ciphertextKeyXChaCha20);
                const nonceXChaCha20 = await modpack.readFile(nn[1].nonceXChaCha20);
                const nonceAdae = await modpack.readFile(nn[1].nonceAdae);
                const saltPwd = await modpack.readFile(nn[1].saltPwd);
                const cryptFileBlockDataArea = await modpack.readFile(nn[1].cryptFile);
                if (!(ciphertextKeyXChaCha20 && nonceXChaCha20 && nonceAdae && saltPwd && cryptFileBlockDataArea)) {
                    console.warn(`[${this.ModName}] cannot get file from zip`, [nn, ciphertextKeyXChaCha20, nonceXChaCha20, nonceAdae, saltPwd, cryptFileBlockDataArea]);
                    this.logger.warn(`[${this.ModName}] cannot get file from zip [${nn[0]}]`);
                    continue;
                }
                const tryDecrypt = async (password: string) => {
                    const key = await calcKeyFromPasswordBrowser(password, saltPwd);
                    const keyXChaCha20 = await decryptXChaCha20Key(
                        ciphertextKeyXChaCha20,
                        nonceAdae,
                        nonceXChaCha20,
                        key,
                    )
                    return await decryptFile(
                        cryptFileBlockDataArea,
                        keyXChaCha20,
                        nonceXChaCha20,
                    );
                }
                let decryptZip: Uint8Array | undefined = undefined;
                // try read
                try {
                    const savedP = this.tryLoadPassword();
                    if (isString(savedP)) {
                        decryptZip = await tryDecrypt(savedP);
                    }
                } catch (E: Error | any) {
                    this.cleanSavedPassword();
                    console.error(`[${this.ModName}] decrypt error by read saved password`, [nn, E]);
                    this.logger.error(`[${this.ModName}] decrypt error by read saved password [${nn[0]}] [${E?.message ? E.message : E}]`);
                    await window.modSweetAlert2Mod.fire(`Mod[${this.ModName}] ${ST.decryptFailWithWrongSavePassword} [${E?.message ? E.message : E}]`);
                }
                if (!decryptZip) {
                    // try input
                    const inputP = await this.inputPassword(passwordHint);
                    try {
                        decryptZip = await tryDecrypt(inputP);
                    } catch (E: Error | any) {
                        console.error(`[${this.ModName}] decrypt error by input password`, [nn, E]);
                        this.logger.error(`[${this.ModName}] decrypt error by input password [${nn[0]}] [${E?.message ? E.message : E}]`);
                        await window.modSweetAlert2Mod.fire(`Mod[${this.ModName}] ${ST.decryptFailWithWrongInputPassword} [${E?.message ? E.message : E}]`);
                        return;
                    }
                    this.savePassword(inputP);
                }
                if (!decryptZip) {
                    // never go there
                    console.error(`[${this.ModName}] decrypt error, no valid decrypt password`, [nn]);
                    this.logger.error(`[${this.ModName}] decrypt error, no valid decrypt password [${nn[0]}]`);
                    return;
                }
                if (!await this.gModUtils.lazyRegisterNewModZipData(decryptZip)) {
                    console.error(`[${this.ModName}] cannot register new mod zip data`, [nn, decryptZip]);
                    this.logger.error(`[${this.ModName}] cannot register new mod zip data [${nn[0]}]`);
                } else {
                    console.log(`[${this.ModName}] decrypt success`, [nn]);
                    this.logger.log(`[${this.ModName}] decrypt success [${nn[0]}]`);
                }
            }
        } catch (e: any) {
            console.error(e);
            this.logger.error(`[${this.ModName}] decrypt () Error:[${e?.message ? e.message : e}]`);
        }
    }

    // get password from user input
    async inputPassword(passwordHint: string | undefined = undefined) {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call readPassword(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call readPassword(), constructor not completed`);
        }
        try {
            const {value: password} = await window.modSweetAlert2Mod.fireWithOptions({
                title: `${ST.inputPasswordTitle(this.ModName)}\n${passwordHint ? passwordHint : ''}`,
                input: 'password',
                inputLabel: `${ST.password}`,
                inputPlaceholder: `${ST.inputPasswordPlaceholder(this.ModName)}`,
                inputAttributes: {
                    maxlength: '1000',
                    autocapitalize: 'off',
                    autocorrect: 'off'
                },
            });

            if (password) {
                await window.modSweetAlert2Mod.fire(`${ST.yourInputPasswordIs} ${password}`);
            }

            return password;
        } catch (e) {
            console.error(e);
        }
        return undefined;
    }

    cleanSavedPassword() {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call savePassword(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call savePassword(), constructor not completed`);
        }
        // clean saved password in localstorage
        localStorage.removeItem(`SimpleCryptWrapper_${this.ModName}_password`);
    }

    tryLoadPassword() {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call tryLoadPassword(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call tryLoadPassword(), constructor not completed`);
        }
        // try load from localstorage
        const p = localStorage.getItem(`SimpleCryptWrapper_${this.ModName}_password`);
        if (isString(p)) {
            return p;
        }
        return undefined;
    }

    savePassword(password: string) {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call savePassword(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call savePassword(), constructor not completed`);
        }
        // encrypt and save to localstorage
        localStorage.setItem(`SimpleCryptWrapper_${this.ModName}_password`, password);
    }

    init() {
        if (!this.infoCreateOk) {
            console.log(`[SimpleCryptWrapperModPack] cannot call init(), constructor not completed`);
            this.logger.log(`[SimpleCryptWrapperModPack] cannot call init(), constructor not completed`);
        }
    }
}
