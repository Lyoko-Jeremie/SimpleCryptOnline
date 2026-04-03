// 1. 定义与 libsodium 兼容的类型
export type Uint8ArrayOutputFormat = 'uint8array';
// libsodium 通常支持 'hex', 'base64', 'text' 等字符串输出格式
export type StringOutputFormat = 'hex' | 'base64' | 'text';

// 2. 实现函数重载签名
export function randombytes_buf(length: number, outputFormat?: Uint8ArrayOutputFormat | null): Uint8Array;
export function randombytes_buf(length: number, outputFormat: StringOutputFormat): string;

// 3. 核心实现
export function randombytes_buf(
    length: number,
    outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null
): Uint8Array | string {

    // -- 第一步：生成密码学安全的随机 Buffer --
    const buf = new Uint8Array(length);
    const cryptoObj = globalThis.crypto;

    if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
        throw new Error("当前环境不支持密码学安全的随机数生成器 (Web Crypto API)。");
    }

    // 处理 getRandomValues 的 64KB (65536) 限制
    const MAX_BYTES = 65536;
    for (let offset = 0; offset < length; offset += MAX_BYTES) {
        const chunk = buf.subarray(offset, offset + MAX_BYTES);
        cryptoObj.getRandomValues(chunk);
    }

    // -- 第二步：处理输出格式 (Output Format) --
    const format = outputFormat || 'uint8array';

    if (format === 'uint8array') {
        return buf;
    }

    if (format === 'hex') {
        // 转换为十六进制字符串
        // 使用 Array.from 和 padStart 保证两位前导 0
        return Array.from(buf)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    if (format === 'base64') {
        // 转换为 Base64 字符串
        // 注意：为了防止极大数据导致 "Maximum call stack size exceeded"，需要分块转换
        let binaryString = '';
        const CHUNK_SIZE = 8192;
        for (let i = 0; i < buf.length; i += CHUNK_SIZE) {
            const chunk = buf.subarray(i, i + CHUNK_SIZE);
            // 利用 String.fromCharCode 将 byte 转为字符
            binaryString += String.fromCharCode.apply(null, chunk as unknown as number[]);
        }
        // 浏览器原生支持 btoa 进行 base64 编码 (HTTP下也可用)
        return globalThis.btoa(binaryString);
    }

    if (format === 'text') {
        // 尽管随机字节转 text 通常是乱码，但为了接口完整性提供支持
        return new TextDecoder().decode(buf);
    }

    throw new Error(`Unsupported output format: ${format}`);
}
