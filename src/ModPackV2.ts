
// 用于表示 JS 内存树对象的接口
export interface JsFileNode {
    name: string;
    isFile: boolean;
    size?: number;             // 仅文件有
    blockIndex?: number;       // 仅文件有
    children?: Record<string, JsFileNode>; // 仅目录有，使用 Map/Record 方便访问
}

export class ZeroCopyTree {
    private treeData: DataView;
    private stringPool: Buffer;
    private decoder = new TextDecoder('utf-8');

    constructor(treeBuffer: Buffer, poolBuffer: Buffer) {
        // 零拷贝视图
        this.treeData = new DataView(treeBuffer.buffer, treeBuffer.byteOffset, treeBuffer.length);
        this.stringPool = poolBuffer;
    }

    // =========================================================
    // 模式 1：零拷贝原地快速操作 (In-place Operations)
    // 适合游戏运行时、资源极速定位、遍历
    // =========================================================

    /**
     * 原地读取局部名称
     */
    private readLocalName(nodeIndex: number): string {
        const offset = nodeIndex * 32;
        const nameOffset = this.treeData.getUint32(offset, true);
        const nameLen = this.treeData.getUint16(offset + 4, true);
        return this.decoder.decode(this.stringPool.subarray(nameOffset, nameOffset + nameLen));
    }

    /**
     * 原地快速列出目录下的所有内容 (类似 fs.readdir)
     * 时间复杂度: O(ChildCount)，完全不涉及递归和对象创建
     */
    public readDirInPlace(dirNodeIndex: number = 0): string[] {
        const offset = dirNodeIndex * 32;
        const isDir = (this.treeData.getUint16(offset + 6, true) & 1) === 1;
        if (!isDir) throw new Error("Not a directory");

        const childStart = this.treeData.getUint32(offset + 12, true);
        const childCount = this.treeData.getUint32(offset + 16, true);

        const list = [];
        // 直接根据子节点连续存放的特性进行切片读取
        for (let i = 0; i < childCount; i++) {
            list.push(this.readLocalName(childStart + i));
        }
        return list;
    }

    /**
     * 原地快速查询单层目录下的目标子节点 (利用二分查找)
     * 时间复杂度: O(log ChildCount)
     */
    public findChildInPlace(dirNodeIndex: number, targetName: string): number | null {
        // ... (同理获取 childStart 和 childCount)
        const childStart = this.treeData.getUint32(dirNodeIndex * 32 + 12, true);
        const childCount = this.treeData.getUint32(dirNodeIndex * 32 + 16, true);

        let left = 0;
        let right = childCount - 1;

        while (left <= right) {
            const mid = (left + right) >> 1; // 快速除以2
            const midIndex = childStart + mid;
            const midName = this.readLocalName(midIndex);

            if (midName === targetName) return midIndex;
            if (midName < targetName) left = mid + 1;
            else right = mid - 1;
        }
        return null;
    }


    // =========================================================
    // 模式 2：完整构建 JS 对象 (Object Instantiation)
    // 适合给 UI 界面绑定数据、需要反复进行高频查询的开发工具场景
    // =========================================================

    /**
     * 一次性将整个二进制树解析为常规的 JavaScript 嵌套对象
     * 时间复杂度: O(N) 一次遍历
     */
    public buildJsObjectTree(nodeIndex: number = 0): JsFileNode {
        const offset = nodeIndex * 32;
        const flags = this.treeData.getUint16(offset + 6, true);
        const isDir = (flags & 1) === 1;

        const node: JsFileNode = {
            name: this.readLocalName(nodeIndex),
            isFile: !isDir
        };

        const targetIndex = this.treeData.getUint32(offset + 12, true);
        const targetSize = this.treeData.getUint32(offset + 16, true);

        if (isDir) {
            node.children = {};
            // 递归遍历该目录块的连续子节点
            for (let i = 0; i < targetSize; i++) {
                const childNodeIndex = targetIndex + i;
                const childObj = this.buildJsObjectTree(childNodeIndex);
                node.children[childObj.name] = childObj;
            }
        } else {
            node.blockIndex = targetIndex;
            node.size = targetSize;
        }

        return node;
    }
}
