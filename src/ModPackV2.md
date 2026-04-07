# JeremieModLoader (JML) 封包文件结构设计文档 (V2)

## 1. 设计初衷 (Design Intent)

在游戏与应用的 Mod 封包场景中，传统的封包格式（如基于 BSON 或纯 JSON 的方案）存在严重的解析性能瓶颈。它们在加载时会触发大量的内存分配（反序列化），产生垃圾回收（GC）压力，且不支持真正意义上的零拷贝访问。同时，常规打包格式（如 ZIP）在配合现代流密码（如 XChaCha20）进行原地解密时，存在对齐困难、易受填充预言机攻击等安全与性能问题。

因此，本规范旨在重新设计一套**面向数据设计 (Data-Oriented Design)** 的现代混合索引虚拟文件系统架构。

## 2. 设计目标与要求 (Design Goals)

本架构设计的核心旨在同时满足以下严苛的工业级要求：

1. **极致零拷贝 (Zero-Copy)**：通过固定结构的连续数组和视图映射（TypedArray/DataView），消除加载时的反序列化开销，实现纳秒级启动。

2. **完美的原地加解密 (In-place Crypto)**：强制实行 **64 字节块对齐 (Block Alignment)**，完美契合 XChaCha20 的 64 字节内部计数器，允许利用绝对块编号作为 Counter 进行无拷贝流式原地解密。

3. **混合查询能力**：

    * 支持 **O(1) 绝对路径极速定位**。

    * 支持类似 `fs.readdir` 的**层级目录枚举**与 O(log N) 局部二分查找。

    * 随时支持从零拷贝视图中提取完整的常规 JavaScript 嵌套对象树。

4. **灾难恢复与二进制审查 (Inspection & Recovery)**：数据流区保留冗余的局部文件头（包含完整路径明文），便于 Hex 编辑器人工审查以及在索引损坏时重建整棵文件树。

5. **无缝 UTF-8 支持**：不再依赖容易出错的 `\0` (Null-terminator) 结尾，采用长度前缀（Length-prefix）完美兼容各语言与特殊字符。

## 3. 整体文件布局 (Overall File Layout)

封包文件采用严格的块状设计，**除基础头部外，所有区块和子结构均严格对齐至 64 字节边界**。文件后缀建议采用 `.modpack` 或 `.modpack.crypt`。

```text
[ 全局文件头 Global Header ] (定长 128 字节)
--------------------------------------------------
[ 主区块偏移表 ] (定长 128 字节，记录下方各区块起止块和长度，64字节对齐)
--------------------------------------------------
[ 文件元数据信息区 ModMeta ] (明文 JSON 字符串，包含算法参数/Nonce等，64字节对齐+尾部0填充)
--------------------------------------------------
[ bootJson 引导信息区 ] (明文 JSON 字符串，64字节对齐+尾部0填充)
--------------------------------------------------
[ 集中索引区 Central Index ] (结构化元数据区)
  ├─ [ Hash Index Array ] (用于 O(1) 全路径定位，数组，64字节对齐+尾部0填充)
  ├─ [ Tree Node Array ]  (用于目录遍历和树状展示，扁平二分树数组，64字节对齐+尾部0填充)
  └─ [ String Pool ]      (字符串池，仅存放局部文件名，64字节对齐+尾部0填充)
--------------------------------------------------
[ 文件流区 File Stream Region ] (由 Local Header 和 Data 交替组成)
  ├─ [ Local Header 1 ]   (起始于 64 字节边界，包含全路径，尾部0填充补齐到 64 字节)
  ├─ [ File Data 1 ]      (严格起始于新的 64 字节边界，密文/明文，尾部0填充补齐到 64 字节)
  ├─ [ Local Header 2 ]   ...
  ├─ [ File Data 2 ]      ...
```

## 4. 核心区块结构设计与细节

### 4.1 全局文件头 (Global Header)

负责文件识别和全局加解密状态声明。

* `0x00 ~ 0x0F` (16 bytes): Magic Number (`JeremieModLoader`).

* `0x10 ~ 0x13` (4 bytes): 协议版本号 (`uint32`).

* `0x14 ~ 0x17` (4 bytes): 标志位掩码 (`uint32`)。例如 `0x1`=包含加密文件，`0x2`=支持压缩等。

* `0x18 ~ 0x1B` (4 bytes): `HashSeed`，用于解决 `xxHash64` 冲突的完美哈希种子。

* `0x1C ~ 0x33` (24 bytes): `Xchacha20Nonce` (直接存储原始字节)。

* `0x34 ~ 0x53` (32 bytes): `PwhashSalt` (直接存储原始字节)。

* `0x54 ~ 0x7F` (44 bytes): 预留，全 0 填充以凑满 128 字节。

### 4.2 集中索引区 (Central Index)

该区域是零拷贝性能的核心，包含三个紧凑的数据结构。

#### A. Hash Index Array (哈希索引表)

每个条目占 **16 字节**。该数组基于文件完整路径的 Hash 构建。

* `hash_value` (`uint64`, 8 bytes): `xxHash64("完整路径", HashSeed)`。

* `block_index` (`uint32`, 4 bytes): 该文件对应的 `Local Header` 起始块编号。

* `flags` (`uint32`, 4 bytes): 保留/快速状态标位。

#### B. Tree Node Array (拍平的树状节点数组)

每个节点固定占 **32 字节**。利用数组连续性表达树状结构，根目录固定在索引 `0` 处。

* `name_offset` (`uint32`): 局部名在 String Pool 中的字节偏移。

* `name_length` (`uint16`): 局部名的字节长度。

* `flags` (`uint16`): 位元标志，bit 0: `1=目录, 0=文件`。

* `local_hash` (`uint32`): 局部名的短哈希（可选，用于极致二分查找提速）。

* `target_index` (`uint32`):

    * 目录：子节点在 Tree Node Array 中的起始下标索引。

    * 文件：文件对应 Local Header 的绝对块编号 (`Block Index`)。

* `target_size` (`uint32`):

    * 目录：子节点的数量 (`Child Count`)。

    * 文件：文件的真实字节长度 (`Real Length`)。

* `reserved` (12 bytes): 保留。

#### C. File Name String Pool (局部名字符串池)

* **仅存放局部名**（如 `icon.png`，而非 `textures/ui/icon.png`）。

* 字符串直接首尾相连，**不使用 `\0` 结尾**，完全依靠 Tree Node 中的 offset 和 length 切片读取。

### 4.3 文件流区 (File Stream Region)

#### A. 局部文件头 (Local Header)

紧贴在文件真实数据前，必须位于 64 字节边界。

* `magic` (4 bytes): 标识符 `"FILE"`。

* `name_length` (`uint16`, 2 bytes): 完整路径的长度。

* `real_length` (`uint32`, 4 bytes): 文件原始数据的真实长度。

* `flags` (`uint16`, 2 bytes): 标明该文件是否加密、压缩算法字典等。

* `full_path` (`name_length` bytes): **含斜杠的完整文件路径**（UTF-8, 无 `\0`）。用于二进制审查与验证。

* `padding`: 自动填充 `0x00`，确保下一个结构（File Data）绝对从新的 64 字节边界开始。

    * *计算公式: `(64 - ((12 + name_length) % 64)) % 64`*

#### B. 文件数据 (File Data)

严格从新的 64 字节边界起算。

* 若被加密，加解密算法（XChaCha20）的 **初始 Counter 必须等于该数据块的块编号 (Block Index)**。

* 数据结束后，使用 `0x00` 填充，补齐到下一个 64 字节边界。

## 5. 关键细节点与注意事项 (Gotchas & Principles)

### 1. 路径标准化与哈希种子 (Path Normalization & Perfect Hashing)

* **标准化**：所有存入包中的路径，必须强制使用 UNIX 风格正斜杠 `/` 分隔，且**不允许**带有前导或后置斜杠（即 `a/b.txt`，非 `/a/b.txt`）。

* **哈希冲突处理（完美哈希策略）**：在打包期（Pack），通过传入全局头的 `HashSeed` 对所有全路径计算 `xxHash64`。如果发现冲突，打包器**必须**修改 `HashSeed` 并全部重算，直到构建出无冲突的 Hash Index Array。

### 2. 拍平树状数组的两大铁律 (Tree Flattening Rules)

必须在打包工具中严格遵守，否则零拷贝目录遍历将直接崩溃：

* **物理连续性**：同一个目录下的所有子节点，在 `Tree Node Array` 中必须是紧挨着的数组条目。

* **字典序排列**：连续的子节点，必须根据它们的**局部文件名**进行字典排序。这是为了在加载时能够进行 $O(\log N)$ 的二分查找。

### 3. 读取验证闭环 (Verification Loop)

在运行时，当利用 O(1) 哈希定位文件时，步骤必须如下：

1. 通过哈希查出 `Block Index`。

2. 跳转至该区块读取 `Local Header`。

3. **强制验证** `Local Header` 里的明文完整路径与请求路径是否 100% 一致。

4. 验证通过后，方可计算偏移去读取或原地解密底部的 `File Data`。这一步是防止“幽灵文件查寻碰撞”的安全兜底。

### 4. 彻底分离职责 (Separation of Concerns)

* **想要遍历目录、构建 UI 文件树？** 只读 `Tree Node Array` 和 `String Pool`。

* **想要瞬间加载特定文件用于游戏渲染？** 只读 `Hash Index Array` 和 `Local Header`。

两者物理上在同一个文件中，但逻辑上相互隔离，互不拖累，各取所需。
