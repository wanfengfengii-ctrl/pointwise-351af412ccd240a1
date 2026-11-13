# 压实事故封存约定

这是带 merge operand 的小型湖表计数引擎。一个 JSON 包保存 cap、有限 keys、不可变 runs、一个压实 jobs 项和已观察的读请求 observations；数值均为整数。读取只解释包中的 run，不依赖外部存储。事故包的 observations 是当班留下的观测点，不是完整影响范围。

## 业务与输入

- cap 为正整数；keys 为互异字符串。每个键的计数范围为 0..cap，缺行用 null 表示，缺行不等于计数 0。
- bottom run 仅含 seq=0 的 put，每键至多一条，无过期时间；未列出的键初始缺行。其他 run 的记录 seq 为互异正整数。所有记录带互异字符串 id；源输入无 parents 字段。
- 点记录为 {"id":字符串,"key":已声明键,"seq":整数,"op":"put"|"add"|"erase"}。put/value 在 0..cap；add/value 为非零有符号整数。put、add 的 until 可省略、为 null 或非负整数。erase 不带 value、until。
- 范围删除为 {"id":字符串,"seq":整数,"op":"range","lo":字符串,"hi":字符串}，lo<hi，按 Python 字符串序覆盖 [lo,hi)，没有过期时间。
- jobs 恰有一项 {"inputs":[互异run名...],"output":新run名}；至少一个输入，不能选 bottom，输出名不在输入包内。未选 run 仍参与读取。只分析这一次既定压实，不设计调度、发布或修复。
- 查询 snapshot、at 为非负整数；snapshot 大于最大 seq 时仍合法。at 是独立的读取时间，不随 snapshot 自动推算。时间边界 at==until 已过期。

在 snapshot 可见的记录中，按 seq 从新到旧查找同键点记录和覆盖它的范围删除。未过期 add 暂存，已过期 add 跳过。遇到 put、erase 或 range 即停止向旧处查找；未过期 put 提供基值，其余屏障提供缺行。特别地，过期 put 是删除屏障，不暴露更旧 put。若未遇屏障则基值缺行。把暂存的 add 按 seq 从旧到新应用：缺行先按 0 起算，每次计算 min(cap,max(0,旧值+value))，应用后该键存在。没有未过期 add 且基值缺行才返回 null。

压实应在全部合法读请求下保持这一业务结果；不能仅保住最新合计。原读取语义和字段规则不在本轮修改。

## 真实入口与公开观测

reader.load(path) -> 包；reader.read(bundle,snapshot,at) -> {键:整数或null}。
compact.compact(bundle,inputs,output) -> 新包；compact.replay(bundle) 依 jobs 调用 compact，不修改调用方包。结果包中的 run 就是实际压实产物，parents 只作物理血缘，不参与读语义。
reader.with_base(bundle,key,value) 只制作诊断派生包：替换该键 bottom 的基值；value=null 则移除该条底层记录，其余内容不变。

python3 checks.py normal 读取 data/normal.json，核对正常业务，退出 0，输出 NORMAL_COUNTER_READ_OK。
python3 checks.py incident 读取 data/incident.json，核对源包观测并逐项显示压实前后值；存在差异时退出 1，输出 MERGE_VIEW_DIVERGENCE。连续两次从相同包启动应得到同一业务输出。
python3 checks.py demo 显示事故实际差异，退出 0。
logs/incident.log 保存本基线两次真实执行业务 stdout 和退出值。宿主 Python 启动器的缓存警告不属于故障日志。

normal 包公开预期：snapshot=9,at=0 时 x=15,y=9,z=4；snapshot=9,at=100 时 z 缺行，其余不变；snapshot=6,at=100 时 x 缺行、y=9、z=30。事故的指定点源读数在 observations.expected 内，checks.py 不把它当完整诊断答案。

## 分析入口及证书

交付 analysis.py run PATH、analysis.py verify PATH、analysis.py demo PATH；PATH 是同格式包，默认 data/incident.json。run 生成 REPORT.md 和 evidence.json；verify 重算证据并与这两份交付核对，成功退出 0；demo 显示实际键值、相应读请求及证书对应区域。更新现有运行清单，使 verify、demo 走这两个分析入口。报告引用实际源码行号；不改生产源码、既有断言、原包和原日志，反事实另存或嵌入 evidence.json。

影响域有两个视角：
1. 按原包 bottom 的实际基值，列明每键全部差异读域。
2. 对每键单独用 with_base 替换其旧值，其他 run 保持不变；旧值域为 null 与每个 0..cap 整数。完整给出压实前后不等的 (key,snapshot,at,base) 集合。不是让多个键独立取值后猜测联合总量；合计抵消按原包实际值核对即可。

evidence.json 至少包含 version=1、package_sha256、captures、regions、counterfactuals。
package_sha256 为 PATH 原始字节的 SHA-256。
captures 保留正常回归、两次原 incident 命令的 argv、exit、stdout，以及分析中调用原入口得到的见证；正常和事故捕获始终使用未改的公开包，额外 PATH 的分析结果另列。
counterfactuals 保存可重放的派生包、查询、修改位置、修改前后值和原入口输出；每组相邻对照只改变一个记录字段或一个查询参数。它们须能把报告提出的原因区分开，而不是只增加同类事故样本。

regions 是互不重叠的差异区域数组。每项为：
{"key":"a","snapshot":[lo,hi],"at":[lo,hi],"base":[lo,hi],"before":[m,b],"after":[m,b]}
区间均为整数左闭右开，snapshot/at 的 hi=null 表示正无穷；base=null 专指缺行基底，否则为 [lo,hi)，0<=lo<hi<=cap+1。before/after 为 null（结果缺行）或 [m,b]（结果 m*x+b），m 为 0 或 1；base=null 时只允许 m=0。每个区域内的 before、after 必须描述真实结果，且处处不等。区域并集必须恰好等于完整差异域；没有区域表示该键无差异，不能以空输出逃避覆盖。允许按事件边界划分，不要求某一种唯一或最少区域布局。实际基值的差异域通过代入原 bottom 得到，报告须将其写清。计数和时间的数值大小不能成为逐整数展开的循环界。

生产入口用于捕获实际运行和检查见证；完整区域判定须独立解释记录，不调用 reader.resolve/read 或 compact.compact/replay 来充当判定器。允许先捕获 replay 的实际输出 run，然后对前后两组记录作独立分析。verify 必须重建完整区域并核对，不可只抽查提交的几条见证。报告说明如何从有限记录构造区间，以及边界、缺行和屏障处理为何不漏解，给出压实安全与失真的可计算充要判据；不能只写“前后相等即安全”。算法适用于以上合法单次压实包，不扩展为在线通用存储系统。
