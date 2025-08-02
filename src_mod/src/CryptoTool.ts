import {
    ready,
    randombytes_buf,
    crypto_pwhash,
    crypto_pwhash_SALTBYTES,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_PASSWD_MIN,
    crypto_pwhash_PASSWD_MAX,
    crypto_pwhash_ALG_DEFAULT,
    crypto_generichash,
    crypto_aead_chacha20poly1305_keygen,
    crypto_aead_chacha20poly1305_encrypt,
    crypto_aead_chacha20poly1305_decrypt,
    crypto_aead_chacha20poly1305_NPUBBYTES,
    crypto_aead_chacha20poly1305_KEYBYTES,
    crypto_aead_chacha20poly1305_ABYTES,
    to_hex,
    to_base64,
    from_hex,
    from_base64,
    crypto_stream_xchacha20_keygen,
    crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES,
    crypto_stream_xchacha20_xor_ic,
} from 'libsodium-wrappers-sumo';


//  Buffer(nodejs) === Uint8Array(browser)

// :: encrypt ::
// generateNewSalt() -> salt
// user input password -> password
// calcKeyFromPassword(password, salt) -> key
// read file -> file
// encryptFile(file, key) -> {nonce, ciphertext}
// save {nonce, ciphertext, salt} to file

// :: decrypt ::
// read file -> {nonce, ciphertext, salt}
// user input password -> password
// calcKeyFromPassword(password, salt) -> key
// decryptFile(ciphertext, key, nonce) -> file
// save file

export async function generateNewSalt() {
    await ready;
    console.log('crypto_pwhash_SALTBYTES', crypto_pwhash_SALTBYTES);
    console.log('crypto_pwhash', crypto_pwhash);
    console.log('crypto_pwhash_PASSWD_MIN', crypto_pwhash_PASSWD_MIN);
    console.log('crypto_pwhash_PASSWD_MAX', crypto_pwhash_PASSWD_MAX);
    console.log('crypto_aead_chacha20poly1305_keygen', crypto_aead_chacha20poly1305_keygen);
    console.log('crypto_aead_chacha20poly1305_encrypt', crypto_aead_chacha20poly1305_encrypt);
    console.log('crypto_aead_chacha20poly1305_decrypt', crypto_aead_chacha20poly1305_decrypt);
    return randombytes_buf(crypto_pwhash_SALTBYTES, 'uint8array');
}

export async function calcKeyFromPassword(password: string, salt: Uint8Array) {
    await ready;
    // if (!(crypto_pwhash_PASSWD_MIN <= password.length && password.length <= crypto_pwhash_PASSWD_MAX)) {
    //     return Promise.reject(new Error(`password length error, (${crypto_pwhash_PASSWD_MIN}~${crypto_pwhash_PASSWD_MAX})`));
    // }
    if (!(crypto_pwhash_SALTBYTES === salt.length)) {
        return Promise.reject(new Error('salt length error'));
    }
    return crypto_pwhash(
        crypto_aead_chacha20poly1305_KEYBYTES,
        Buffer.from(password),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT,
    );
}


export async function calcKeyFromPasswordBrowser(password: string, salt: Uint8Array) {
    await ready;
    // if (!(crypto_pwhash_PASSWD_MIN <= password.length && password.length <= crypto_pwhash_PASSWD_MAX)) {
    //     return Promise.reject(new Error(`password length error, (${crypto_pwhash_PASSWD_MIN}~${crypto_pwhash_PASSWD_MAX})`));
    // }
    if (!(crypto_pwhash_SALTBYTES === salt.length)) {
        return Promise.reject(new Error('salt length error'));
    }
    return crypto_pwhash(
        crypto_aead_chacha20poly1305_KEYBYTES,
        new TextEncoder().encode(password),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT,
    );
}

export async function encryptFile(data: Uint8Array, keyXChaCha20: Uint8Array, nonceXChaCha20: Uint8Array, blockSize = 64,) {
    await ready;
    if (!(crypto_stream_xchacha20_NONCEBYTES === nonceXChaCha20.length)) {
        return Promise.reject(new Error('nonce length error'));
    }
    if (!(crypto_stream_xchacha20_KEYBYTES === keyXChaCha20.length)) {
        return Promise.reject(new Error('key length error'));
    }
    let blockCount = Math.ceil(data.length / blockSize);
    while (blockCount * blockSize < data.length) {
        const d = crypto_stream_xchacha20_xor_ic(
            data.subarray(blockCount * blockSize, blockCount * blockSize + blockSize),
            nonceXChaCha20,
            blockCount,
            keyXChaCha20,
        );
        data.set(d, blockCount * blockSize);
        blockCount++;
    }
    return data;
}

export async function decryptFile(data: Uint8Array, keyXChaCha20: Uint8Array, nonceXChaCha20: Uint8Array, blockSize = 64,) {
    // for crypto_stream_xchacha20_xor_ic , Decrypting is the same as encrypting in this case . because it is a xor operation.
    return await encryptFile(data, keyXChaCha20, nonceXChaCha20, blockSize);
}

export async function encryptXChaCha20Key(adaeKey: Uint8Array, additionalData: Uint8Array | null = null) {
    await ready;
    const keyXChaCha20 = crypto_stream_xchacha20_keygen();
    const nonceXChaCha20 = await randombytes_buf(crypto_stream_xchacha20_NONCEBYTES);
    const nonceAdae = randombytes_buf(crypto_aead_chacha20poly1305_NPUBBYTES);
    const ciphertextKeyXChaCha20 = crypto_aead_chacha20poly1305_encrypt(keyXChaCha20, additionalData, null, nonceAdae, adaeKey);
    return {
        keyXChaCha20: keyXChaCha20,
        nonceXChaCha20: nonceXChaCha20,
        nonceAdae: nonceAdae,
        ciphertextKeyXChaCha20: ciphertextKeyXChaCha20,
    };
}

export async function decryptXChaCha20Key(
    ciphertextKeyXChaCha20: Uint8Array,
    nonceAdae: Uint8Array,
    nonceXChaCha20: Uint8Array,
    adaeKey: Uint8Array,
    additionalData: Uint8Array | null = null,
) {
    await ready;
    if (!(crypto_aead_chacha20poly1305_NPUBBYTES === nonceAdae.length)) {
        return Promise.reject(new Error('nonceAdae length error'));
    }
    if (!(crypto_stream_xchacha20_NONCEBYTES === nonceXChaCha20.length)) {
        return Promise.reject(new Error('nonceXChaCha20 length error'));
    }
    if (!(crypto_aead_chacha20poly1305_KEYBYTES === adaeKey.length)) {
        return Promise.reject(new Error('adaeKey length error'));
    }
    const keyXChaCha20 = crypto_aead_chacha20poly1305_decrypt(null, ciphertextKeyXChaCha20, additionalData, nonceAdae, adaeKey);
    if (!(crypto_stream_xchacha20_KEYBYTES === keyXChaCha20.length)) {
        return Promise.reject(new Error('keyXChaCha20 length error'));
    }
    return keyXChaCha20;
}
