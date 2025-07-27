import 'core-js/full';
import sodium from 'libsodium-wrappers-sumo';
// @ts-ignore
import xxhash from 'xxhash-wasm';
import JSZip from 'jszip';

(globalThis as any).sodium = sodium;
(globalThis as any).xxhash = xxhash;
(globalThis as any).JSZip = JSZip;
