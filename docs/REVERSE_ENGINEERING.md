# 函数入口定位方法

本文记录 `SC2TimeResume.cs` 里 `ResumeRva` 是怎么来的，以及游戏更新后如何重新定位。

> 仅描述静态分析方法（读取磁盘文件），不涉及注入或修改游戏。

---

## 一、需要定位的东西

| 常量 | 含义 |
| --- | --- |
| `ResumeRva` | “恢复/取消暂停”函数在镜像中的相对偏移 |
| `ResumeFileOffset` | 同一函数在磁盘文件中的偏移 |
| `ResumePrefix` | 函数开头 25 字节的指令指纹 |

程序运行时用 `模块基址 + ResumeRva` 得到真实地址。

---

## 二、RVA 与文件偏移的换算

RVA 是内存中的相对地址，文件偏移是磁盘上的位置，二者按节表换算：

```
文件偏移 = RVA - 所在节的 VirtualAddress + 所在节的 PointerToRawData
```

对 `SC2_x64.exe` 的 `.text` 节，本版本已知的对应关系：

| 功能 | RVA | 文件偏移 |
| --- | --- | --- |
| 恢复 | `0x9EB090` | `0x9EA890` |

用 PE 工具可直接算出，不必手算：

```python
import pefile
pe = pefile.PE("SC2_x64.exe")
print(hex(pe.get_offset_from_rva(0x9EB090)))   # 0x9ea890
```

---

## 三、如何确认一个地址确实是要找的函数

不要凭“地址看着像”就下结论。可靠的判定步骤：

### 1. 反汇编，确认是合法函数开头

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

pe = pefile.PE("SC2_x64.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
rva = 0x9EB090
data = pe.get_data(rva, 64)
for ins in md.disasm(data, pe.OPTIONAL_HEADER.ImageBase + rva):
    print(hex(ins.address), ins.mnemonic, ins.op_str)
```

本版本的恢复入口开头：

```asm
1409eb090  push rbx
1409eb092  sub  rsp, 0x20
1409eb096  mov  edx, dword ptr [rip + 0x50aab2c]
...
```

`push rbx` / `sub rsp, 0x20` 是典型的函数序言，说明这里确实是函数起点，
而不是某条指令的中间。

### 2. 用异常表校核函数边界

x64 程序的 `.pdata` 异常表记录了每个函数的起止 RVA。用它比对可以确认
这个地址是某个函数的 **BeginAddress**，而不是内部跳转目标：

```python
for e in pe.DIRECTORY_ENTRY_EXCEPTION:
    if e.struct.BeginAddress == 0x9EB090:
        print("是函数起点，结束于", hex(e.struct.EndAddress))
```

### 3. 取磁盘字节指纹

选定地址后，把开头一段字节（本项目取 25 字节）作为指纹写进代码。
程序启动时会重新读磁盘比对，不一致就拒绝运行。

本版本的指纹：

```
40534883EC208B155CA A0A058BD981C2BCA3D51103150A4F4C03
```

---

## 四、如何判断这个函数是“恢复”而不是别的

单看反汇编很难直接分辨方向，可用的线索：

1. **构造的对象类型**：函数会构造一个控制对象并交给下游分发函数，
   对象里的类型字段标识事件种类。
2. **交叉引用**：搜索对该地址的 `call` 引用，观察调用方在调用前做了
   哪些状态检查（例如先判断“当前是否处于暂停”）。
3. **原生名称邻近性**：二进制中存在 `NNet::Game::SPauseGameEvent`、
   `NNet::Game::SUnpauseGameEvent` 等名称，可辅助判断方向。

> 字符串只能作为辅助证据，不能单凭它给函数下定义。

---

## 五、游戏更新后怎么重新定位

1. 用新的 `SC2_x64.exe` 计算哈希，更新 `ExpectedSha256`。
2. 更新 `ExpectedVersion`。
3. 在旧地址附近小范围搜索特征字节（很多小版本更新不会改动这段代码）。
4. 用第三节的方法确认新地址确实是函数起点。
5. 更新 `ResumeRva` / `ResumeFileOffset` / `ResumePrefix` 三组常量。
6. **必须实际验证**：程序应能通过校验并成功调用，否则回退检查。

找不到就说明函数被重构，需要重新分析，不要硬套旧地址。

---

## 六、为什么坚持做签名校验

地址错一位就会跳进指令中间执行，轻则崩溃，重则破坏游戏状态。
版本校验是防止误用的唯一手段。宁可拒绝运行，也不要带着错误地址去调用。

---

## 七、分析工具

运行本项目不需要任何第三方库，但复现定位过程需要：

```bash
pip install pefile capstone
```
