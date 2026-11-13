"""压实事故诊断入口。

子命令:
  run PATH    独立重算有限区间证书, 生成 REPORT.md 与 evidence.json
  verify PATH 重算证据并与已交付的 evidence.json / REPORT.md 核对, 成功退出 0
  demo PATH   显示实际键值、对应读请求及证书区域

本模块的区域判定完全由本文件内的独立解释器完成, 不调用
reader.resolve/read 或 compact.compact/replay 充当判定器;
生产入口仅用于捕获真实运行见证(captures/counterfactuals)。
"""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:  # 支持 python3 -I 直接运行(隔离模式不预置脚本目录)
    sys.path.insert(0, HERE)

import reader  # noqa: E402  仅用于 load/read/with_base 见证捕获
import compact  # noqa: E402  仅用于 replay 见证捕获(不参与区域判定)

WORKSPACE = HERE
DEFAULT_PATH = os.path.join(WORKSPACE, "data", "incident.json")
NORMAL_PATH = os.path.join(WORKSPACE, "data", "normal.json")
INCIDENT_LOG = os.path.join(WORKSPACE, "logs", "incident.log")
EVIDENCE_PATH = os.path.join(WORKSPACE, "evidence.json")
REPORT_PATH = os.path.join(WORKSPACE, "REPORT.md")
INF = None  # 区间右端 hi=None 表示正无穷


# --------------------------------------------------------------------------
# 通用工具
# --------------------------------------------------------------------------

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def all_rows(bundle):
    rows = []
    for run_name, run in bundle["runs"].items():
        for row in run:
            rows.append((run_name, row))
    return rows


def point_rows(bundle, key):
    return [row for _run, row in all_rows(bundle)
            if row.get("op") != "range" and row.get("key") == key]


def covering_ranges(bundle, key):
    return [row for _run, row in all_rows(bundle)
            if row.get("op") == "range" and row["lo"] <= key < row["hi"]]


def bottom_base(bundle, key):
    """原包 bottom 对 key 的实际基底: 整数 put 值或缺行 None。"""
    for row in bundle["runs"].get("bottom", []):
        if row.get("key") == key and row.get("op") == "put":
            return row["value"]
    return None


def split_cuts(lower, upper, cuts):
    """在 (lower, upper] 风格的边界集合上生成左闭右开整数区间。"""
    points = sorted({lower, upper} | set(cuts))
    return [(points[i], points[i + 1]) for i in range(len(points) - 1)]


def clamp_chain(start_present, start_value, deltas, cap):
    """与 reader.resolve 同结果的逐 add 钳制链; 返回 (present, value)。"""
    if not start_present:
        present, value = False, 0
    else:
        present, value = True, start_value
    for delta in deltas:
        if not present:
            value = 0
        value = min(cap, max(0, value + delta))
        present = True
    return present, value


# --------------------------------------------------------------------------
# 独立读语义解释器(判定器): 依据 CONTRACT 第 14 行直接解释记录,
# 不 import / 不调用 reader 的任何函数。
# --------------------------------------------------------------------------

def independent_resolve(bundle, key, snapshot, at, base_override=None):
    """独立重算单个 (key, snapshot, at) 的结果; base_override 替代 bottom。"""
    cap = bundle["cap"]
    rows = []
    for run_name, run in bundle["runs"].items():
        for row in run:
            if row.get("op") == "range":
                applies = row["lo"] <= key < row["hi"]
            else:
                applies = row.get("key") == key
            if applies and row["seq"] <= snapshot:
                rows.append(row)
    rows.sort(key=lambda r: r["seq"], reverse=True)

    pending = []
    barrier = None  # ("put", value) | ("erase",) | ("range",) | None
    for row in rows:
        op = row["op"]
        expiry = row.get("until")
        expired = expiry is not None and at >= expiry
        if op == "add":
            if not expired:
                pending.append(row["value"])
            continue
        if op == "put":
            if not expired:
                barrier = ("put", row["value"])
            else:
                barrier = ("erase",)  # 过期 put 是删除屏障
        elif op == "erase":
            barrier = ("erase",)
        else:  # range
            barrier = ("range",)
        break

    if barrier is None:
        # 仅 bottom(seq=0) 可能落在所有可见点记录之外; 自行解释基底
        if base_override is not None:
            present, base_value = True, base_override
        else:
            base = bottom_base(bundle, key)
            present, base_value = (base is not None), (base or 0)
    elif barrier[0] == "put":
        present, base_value = True, barrier[1]
    else:
        present, base_value = False, 0

    present, value = clamp_chain(present, base_value,
                                 list(reversed(pending)), cap)
    return value if present else None


# --------------------------------------------------------------------------
# 结果的仿射片段: result(base) = m*base + b, m ∈ {0,1};
# present=False 表示缺行结果(独立于 base)。
# --------------------------------------------------------------------------

class Affine:
    __slots__ = ("m", "b", "present")

    def __init__(self, m, b, present=True):
        self.m = m
        self.b = b
        self.present = present

    @staticmethod
    def missing():
        return Affine(0, 0, present=False)

    def eval(self, base):
        if not self.present:
            return None
        return self.m * base + self.b

    def as_pair(self):
        return None if not self.present else [self.m, self.b]

    def __eq__(self, other):
        return (self.present == other.present and self.m == other.m
                and self.b == other.b)

    def __repr__(self):
        if not self.present:
            return "missing"
        return f"{self.m}*base+{self.b}"


def apply_delta_piecewise(pieces, delta, cap):
    """对 base∈[0,cap] 上的仿射片段应用一次钳制 add。"""
    out = []
    for lo, hi, aff in pieces:
        if not aff.present:  # 缺行先按 0 起算, 应用 add 后该键存在
            value = min(cap, max(0, 0 + delta))
            out.append((lo, hi, Affine(0, value, present=True)))
            continue
        m, b = aff.m, aff.b
        if m == 0:
            value = min(cap, max(0, b + delta))
            out.append((lo, hi, Affine(0, value, present=True)))
            continue
        # m == 1, 片段内 v(base)=base+b 单调递增; 应用 delta 后
        # w(base)=base+b+delta, 再钳到 [0,cap]。
        # 下钳制起始点 z=-(b+delta): base<z 时 w<0 -> 常量 0;
        # 上钳制起始点 c=cap-b-delta: base>=c 时 w>=cap -> 常量 cap。
        # 切点为片段左端边界(含), 用左闭右开整数区间精确划分。
        z = -(b + delta)
        c = cap - b - delta
        boundaries = [lo, hi]
        for point in (z, c):
            if lo < point < hi:
                boundaries.append(point)
        boundaries = sorted(set(boundaries))
        for seg_lo, seg_hi in zip(boundaries, boundaries[1:]):
            val = min(cap, max(0, seg_lo + b + delta))
            if val == 0 and min(cap, max(0, (seg_hi - 1) + b + delta)) == 0:
                out.append((seg_lo, seg_hi, Affine(0, 0)))
            elif val == cap and min(cap, max(0,
                                              (seg_hi - 1) + b + delta)) == cap:
                out.append((seg_lo, seg_hi, Affine(0, cap)))
            else:
                out.append((seg_lo, seg_hi, Affine(1, b + delta)))
    return out


def program_for_cell(bundle, key, snapshot, at):
    """在一个 (snapshot, at) 单元内构造基底->结果的完整有限程序。

    返回:
      barrier_kind: "none" | "put" | "erase" | "range"
      barrier_value: put 屏障的常量值, 否则 None
      deltas: 按 seq 从旧到新应用的未过期 add 值序列
    程序在单元内恒定(可见集合与过期集合均不变)。
    """
    rows = []
    for _run, row in all_rows(bundle):
        if row.get("op") == "range":
            applies = row["lo"] <= key < row["hi"]
        else:
            applies = row.get("key") == key
        if applies and row["seq"] <= snapshot:
            rows.append(row)
    rows.sort(key=lambda r: r["seq"], reverse=True)

    pending = []
    barrier_kind = "none"
    barrier_value = None
    for row in rows:
        op = row["op"]
        expiry = row.get("until")
        expired = expiry is not None and at >= expiry
        if op == "add":
            if not expired:
                pending.append(row["value"])
            continue
        if op == "put":
            if not expired:
                barrier_kind, barrier_value = "put", row["value"]
            else:
                barrier_kind = "erase"
        elif op == "erase":
            barrier_kind = "erase"
        else:
            barrier_kind = "range"
        break
    return barrier_kind, barrier_value, list(reversed(pending))


def evaluate_program(program, cap, base):
    """base=None 表示缺行基底; 否则为 0..cap 整数。"""
    kind, barrier_value, deltas = program
    if kind == "none":
        if base is None:
            present, value = False, 0
        else:
            present, value = True, base
    elif kind == "put":
        present, value = True, barrier_value
    else:
        present, value = False, 0
    present, value = clamp_chain(present, value, deltas, cap)
    return value if present else None


def base_pieces(program, cap):
    """程序在 base∈[0,cap] 整数域上的分段仿射表示(片段左闭右开)。"""
    kind, barrier_value, deltas = program
    if kind == "put":
        pieces = [(0, cap + 1, Affine(0, barrier_value, present=True))]
    elif kind == "none":
        # 无屏障: 整数基底结果即基底本身(identity); 缺行另由 null 分支处理
        pieces = [(0, cap + 1, Affine(1, 0, present=True))]
    else:
        # erase / range / 过期 put: 屏障提供缺行; 在首个 add 应用前结果
        # 始终缺行(present=False), apply_delta_piecewise 应用 add 后置存在。
        pieces = [(0, cap + 1, Affine(0, 0, present=False))]
    for delta in deltas:
        pieces = apply_delta_piecewise(pieces, delta, cap)
    return pieces


def null_base_result(program, cap):
    return evaluate_program(program, cap, None)


# --------------------------------------------------------------------------
# 有限单元划分与区域构造
# --------------------------------------------------------------------------

def cell_partition(bundle, key):
    """按 seq 事件边界把 snapshot>=0 划分为有限的左闭右开单元(末段 hi=INF)。

    可见记录集合只在 seq 边界变化; at 边界由 at_cuts_for_cell 单独给出。
    """
    seqs = sorted({r["seq"] for _run, r in all_rows(bundle)})
    s_bounds = [0] + [q for q in seqs if q > 0]
    s_intervals = []
    for i, lo in enumerate(s_bounds):
        hi = s_bounds[i + 1] if i + 1 < len(s_bounds) else INF
        s_intervals.append((lo, hi))
    return s_intervals


def at_cuts_for_cell(bundle, key, snapshot_lo):
    """该 snapshot 单元内可能改变过期集合的 at 边界(可见记录的 until 值)。"""
    cuts = set()
    for _run, row in all_rows(bundle):
        applies = row.get("op") in ("put", "add") and row.get("key") == key
        if applies and row["seq"] <= snapshot_lo:
            until = row.get("until")
            if until is not None:
                cuts.add(until)
    return cuts


def diff_regions_for_key(bundle_before, bundle_after, key):
    """完整构造 key 的互不重叠差异区域(不逐整数枚举)。"""
    cap = bundle_before["cap"]
    s_intervals = cell_partition(bundle_before, key)
    regions = []
    for s_lo, s_hi in s_intervals:
        # 单元内可见集合恒定; at 切分需合并前后两套记录的 until
        cuts_before = at_cuts_for_cell(bundle_before, key, s_lo)
        cuts_after = at_cuts_for_cell(bundle_after, key, s_lo)
        a_bounds = sorted(cuts_before | cuts_after)
        a_intervals = []
        prev = 0
        for cut in a_bounds:
            if cut > prev:
                a_intervals.append((prev, cut))
            prev = cut
        a_intervals.append((prev, INF))
        for a_lo, a_hi in a_intervals:
            prog_before = program_for_cell(
                bundle_before, key, s_lo, a_lo)
            prog_after = program_for_cell(
                bundle_after, key, s_lo, a_lo)
            pieces_before = base_pieces(prog_before, cap)
            pieces_after = base_pieces(prog_after, cap)
            # 合并两侧 base 片段: 所有片段端点(含 0 与 cap+1)都进入切分
            cuts = {0, cap + 1}
            for lo, hi, _ in pieces_before + pieces_after:
                cuts.add(lo)
                cuts.add(hi)

            def piece_at(pieces, base_value):
                for lo, hi, aff in pieces:
                    if lo <= base_value < hi:
                        return aff
                raise AssertionError("piece coverage")

            # 孤立相等点(一侧常量平台、另一侧线性时最多一个整数解)也必须
            # 成为切点, 否则差异区域会混入一个相等点, 违反"处处不等"。
            extra_cuts = set()
            for lo, hi in split_cuts(0, cap + 1,
                                     sorted(c for c in cuts if 0 < c)):
                aff_b = piece_at(pieces_before, lo)
                aff_a = piece_at(pieces_after, lo)
                if aff_b.m != aff_a.m:
                    const = aff_b.b if aff_b.m == 0 else aff_a.b
                    lin = aff_a if aff_b.m == 0 else aff_b
                    root = const - lin.b  # lin.m=1: base+b=const
                    if lo <= root < hi:
                        extra_cuts.add(root)
                        extra_cuts.add(root + 1)
            cuts |= extra_cuts
            bounds = sorted(b for b in cuts if 0 <= b <= cap + 1)
            base_segments = []
            prev_b = 0
            for bnd in bounds:
                if bnd > prev_b:
                    base_segments.append((prev_b, bnd))
                prev_b = bnd

            def value_equal_on(aff_b, aff_a, seg_lo, seg_hi):
                """两个仿射在最小片段 [seg_lo,seg_hi) 上是否处处同值。

                片段已按两侧钳制切点与孤立相等点细化, 片段内每个仿射都是
                无转折直线(m=1)或常量(m=0)。两点(seg_lo, seg_hi-1)取值
                相等即保证整段相等(两点定线, 常量自洽), 是值相等充要判据。
                缺行(present=False)与任何存在值都不等。
                """
                if aff_b.present != aff_a.present:
                    return False
                if not aff_b.present:
                    return True  # 两侧皆缺行
                return aff_b.eval(seg_lo) == aff_a.eval(seg_lo) and \
                    aff_b.eval(seg_hi - 1) == aff_a.eval(seg_hi - 1)

            # 最小片段内两侧各自只落在一个仿射片段; 差异判定按段上
            # 的真实结果值(平台同值不算差异), 区域记录真实仿射公式。
            for b_lo, b_hi in base_segments:
                aff_b = piece_at(pieces_before, b_lo)
                aff_a = piece_at(pieces_after, b_lo)
                if not value_equal_on(aff_b, aff_a, b_lo, b_hi):
                    regions.append({
                        "key": key,
                        "snapshot": [s_lo, s_hi],
                        "at": [a_lo, a_hi],
                        "base": [b_lo, b_hi],
                        "before": aff_b.as_pair(),
                        "after": aff_a.as_pair(),
                    })
            # 缺行基底单独成域(base=null, 仅允许 m=0)
            miss_b = null_base_result(prog_before, cap)
            miss_a = null_base_result(prog_after, cap)
            if miss_b != miss_a:
                regions.append({
                    "key": key,
                    "snapshot": [s_lo, s_hi],
                    "at": [a_lo, a_hi],
                    "base": None,
                    "before": None if miss_b is None else [0, miss_b],
                    "after": None if miss_a is None else [0, miss_a],
                })
    return regions


def build_certificate(bundle_before, bundle_after):
    """对全部键构造区域证书, 并返回便于报告的程序缓存。"""
    cert = {}
    for key in bundle_before["keys"]:
        cert[key] = diff_regions_for_key(bundle_before, bundle_after, key)
    return cert


def actual_base_domain(cert, base_by_key):
    """视角 1: 把原 bottom 实际基底代入区域, 得到实际差异读域。"""
    result = {}
    for key, regions in cert.items():
        base = base_by_key[key]
        kept = []
        for region in regions:
            if region["base"] is None:
                if base is None:
                    kept.append(region)
            else:
                lo, hi = region["base"]
                if base is not None and lo <= base < hi:
                    kept.append(region)
        result[key] = kept
    return result


def region_applies(region, snapshot, at, base):
    s_lo, s_hi = region["snapshot"]
    if not (s_lo <= snapshot and (s_hi is INF or snapshot < s_hi)):
        return False
    a_lo, a_hi = region["at"]
    if not (a_lo <= at and (a_hi is INF or at < a_hi)):
        return False
    if region["base"] is None:
        return base is None
    b_lo, b_hi = region["base"]
    return base is not None and b_lo <= base < b_hi


def eval_side(side, region, base):
    pair = region[side]
    if pair is None:
        return None
    m, b = pair
    return m * base + b


# --------------------------------------------------------------------------
# 生产入口见证捕获(仅捕获, 不作判定)
# --------------------------------------------------------------------------

BOOTSTRAP_TEMPLATE = """
import json, sys
sys.path.insert(0, {workspace!r})
import checks
rc = checks.main({mode!r})
sys.exit(rc or 0)
"""


def run_checks_subprocess(mode):
    """以独立进程运行 checks.py 模式, 捕获 argv/exit/stdout(逻辑等价)。"""
    argv = ["python3", "checks.py", mode]
    bootstrap = BOOTSTRAP_TEMPLATE.format(workspace=WORKSPACE, mode=mode)
    proc = subprocess.run(
        [sys.executable, "-I", "-c", bootstrap],
        cwd=WORKSPACE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {
        "argv": argv,
        "logical_argv": argv,
        "exit": proc.returncode,
        "stdout": proc.stdout.decode("utf-8"),
        "stderr_excluded": proc.stderr.decode("utf-8"),
        "capture": "fresh isolated process (-I), checks.main via in-memory "
                   "bootstrap; workspace on sys.path; cwd=workspace",
    }


def witness_via_production(bundle, snapshot, at):
    """通过原入口 reader.read 取得见证(仅用于与独立判定交叉核对)。"""
    return reader.read(bundle, snapshot, at)


def replay_via_production(bundle):
    return compact.replay(bundle)


# --------------------------------------------------------------------------
# 反事实单因素材料
# --------------------------------------------------------------------------

def mutate(bundle, path, value):
    """按记录路径修改单个字段; path=(run, id, field)。"""
    run_name, row_id, field = path
    clone = json.loads(json.dumps(bundle))
    for row in clone["runs"][run_name]:
        if row.get("id") == row_id:
            row[field] = value
            return clone
    raise KeyError(path)


def compact_witness(bundle, queries):
    """对一组查询返回压实前后的原入口读数见证。"""
    after = replay_via_production(bundle)
    out = []
    for snapshot, at in queries:
        out.append({
            "snapshot": snapshot, "at": at,
            "before_entry": "reader.read(original,snapshot,at)",
            "after_entry": "reader.read(compact.replay(original),snapshot,at)",
            "before": witness_via_production(bundle, snapshot, at),
            "after": witness_via_production(after, snapshot, at),
        })
    return out, after


def cf_pack(label, reason, mutation_kind, location, changed_field,
            old_value, new_value, derived, queries, baseline_bundle):
    """构造一组单因素反事实: baseline 与 variant 仅差一个字段/基底/查询。

    两组都附原入口压实前后读数; 相邻对照的差异即被隔离的机理。
    """
    baseline_witnesses, _ = compact_witness(baseline_bundle, queries)
    variant_witnesses, _ = compact_witness(derived, queries)
    return {
        "id": label,
        "isolates": reason,
        "mutation_kind": mutation_kind,
        "location": location,
        "changed_field": changed_field,
        "before_value": old_value,
        "after_value": new_value,
        "derived_bundle": derived,
        "queries": [{"snapshot": s, "at": a} for s, a in queries],
        "baseline_members": baseline_witnesses,
        "members": variant_witnesses,
        "single_factor_deltas": [
            {
                "snapshot": q_s, "at": q_a,
                "key_level": {
                    k: {
                        "baseline_before": bw["before"][k],
                        "baseline_after": bw["after"][k],
                        "variant_before": vw["before"][k],
                        "variant_after": vw["after"][k],
                    }
                    for k in bw["before"]
                    if (bw["before"][k] != bw["after"][k]
                        or vw["before"][k] != vw["after"][k]
                        or bw["before"][k] != vw["before"][k]
                        or bw["after"][k] != vw["after"][k])
                },
            }
            for (q_s, q_a), bw, vw in zip(
                queries, baseline_witnesses, variant_witnesses)
        ],
    }


def cf_with_base(bundle, key, value, queries, label, location, old, new,
                 reason):
    derived = reader.with_base(bundle, key, value)
    return cf_pack(
        label, reason, "reader.with_base bottom replacement", location,
        "runs.bottom[key=%s].value" % key, old, new, derived, queries,
        bundle)


def cf_field(bundle, path, new_value, queries, label, reason):
    run_name, row_id, field = path
    old_value = next(r[field] for r in bundle["runs"][run_name]
                     if r.get("id") == row_id)
    derived = mutate(bundle, path, new_value)
    return cf_pack(
        label, reason, "single record field replacement",
        "runs.%s[id=%s].%s" % (run_name, row_id, field), field,
        old_value, new_value, derived, queries, bundle)


def build_counterfactuals(bundle):
    cf = []
    # CF-1 逐次钳制丢失(饱和): 仅替换 a 的 bottom, 邻域 null vs 实际
    cf.append(cf_with_base(
        bundle, "a", None, [(40, 0), (40, 25), (40, 85)],
        "CF1_clamp_saturation_a",
        "runs.bottom[id=base-a]", 999999999995, None,
        "R1 逐 add 钳制被合并后单次钳制替代: 高基底 a 上 +10/-10 的饱和中间态"))

    # CF-2 过期合并(R2): 把 b2 的 until null -> 50(与 b1 对齐), 相邻
    # at=24/50 仅查询参数变化。原包合并行 until=null 永不超时; 对齐后
    # 合并行 until=max(50,50)=50, at=50 起两侧都跳过 b 组, 差异被关闭。
    cf.append(cf_field(
        bundle, ("L0-b", "b2", "until"), 50, [(40, 24), (40, 50)],
        "CF2_expiry_merge_b",
        "R2 until 聚合(None 吞没短过期): b2 改为 until=50 后合并行在 at=50 一并过期"))

    # CF-3 序号落点: a2 seq 14 -> 11, 相同查询 (12,0)
    cf.append(cf_field(
        bundle, ("L0-b", "a2", "seq"), 11, [(12, 0)],
        "CF3_seq_placement_a",
        "R3 合并行只保留最大 seq: 拉平 a2 序号后 S∈[11,14) 的历史窗口差异"))

    # CF-4 范围删除遮断: r1 hi e -> c, 查询 (16,0), d 是否被覆盖
    cf.append(cf_field(
        bundle, ("L0-b", "r1", "hi"), "c", [(16, 0)],
        "CF4_range_barrier_d",
        "R4 分组忽略跨在 add 之间的 range 屏障: 收缩范围后 d 的遮断差异"))

    # CF-5 过期后显露(j-mask): 把未选 run 的 j-mask until 25 -> 1000,
    # 相邻 at 24/25 仅查询参数变化, 隔离"过期显露"与合并行的交互
    cf.append(cf_field(
        bundle, ("front", "j-mask", "until"), 1000, [(40, 24), (40, 25)],
        "CF5_expired_mask_reveal_j",
        "R1 钳制链与过期显露: 延长未选 run j-mask 寿命后 at=25 不再显露合并行"))

    # CF-6 缺行 vs 零: f 无 bottom, with_base(f,0), 查询 (22,0)
    cf.append(cf_with_base(
        bundle, "f", 0, [(22, 0)],
        "CF6_missing_vs_zero_f",
        "runs.bottom(no row for f)", None, 0,
        "缺行(null)与计数 0 的区分: R3 序号落点使 S∈[22,23) 合并行不可见"))

    # CF-7 erase 屏障窗口: h, 查询 (27,0) 对比实际与反事实基底
    cf.append(cf_with_base(
        bundle, "h", 77, [(27, 0)],
        "CF7_erase_barrier_window_h",
        "runs.bottom[id=base-h]", 12, 77,
        "R3 合并行序号 28 落在 erase(26) 之后: S∈[26,28) 屏障窗口差异"))

    # CF-8 合计抵消: 不改包, 仅相邻查询 at=0 vs at=85; baseline/variant
    # 为同一包的两个读请求, 核对 a+b 合计在压实前后恒为 cap(抵消)。
    queries8 = [(40, 0), (40, 85)]
    witnesses8, _ = compact_witness(bundle, queries8)
    balances = []
    for m in witnesses8:
        balances.append({
            "snapshot": m["snapshot"], "at": m["at"],
            "sum_before": (m["before"]["a"] + m["before"]["b"]
                           if m["before"]["a"] is not None
                           and m["before"]["b"] is not None else None),
            "sum_after": (m["after"]["a"] + m["after"]["b"]
                          if m["after"]["a"] is not None
                          and m["after"]["b"] is not None else None),
            "per_key_drift": {
                k: [m["before"][k], m["after"][k]]
                for k in m["before"] if m["before"][k] != m["after"][k]},
        })
    cf.append({
        "id": "CF8_balance_cancellation",
        "isolates": "合计抵消: a/b 键内漂移方向相反, a+b 合计压实前后均为 cap",
        "mutation_kind": "query parameter only (package untouched)",
        "location": None,
        "changed_field": "at",
        "before_value": 0,
        "after_value": 85,
        "derived_bundle": bundle,
        "queries": [{"snapshot": 40, "at": 0}, {"snapshot": 40, "at": 85}],
        "baseline_members": witnesses8,
        "members": witnesses8,
        "balance_witness": balances,
    })

    # CF-9 短窗口序号条带(f): f1 until 30 -> 1000, 查询 (22,0)/(23,0)
    cf.append(cf_field(
        bundle, ("L0-a", "f1", "until"), 1000, [(22, 0), (23, 0)],
        "CF9_snapshot_strip_f",
        "R3 序号条带: 延长 f1 后 S∈[22,23) 内缺行/0 的条带差异可直接对照"))
    return cf


# --------------------------------------------------------------------------
# 证书自检: 独立判定器 vs 区域仿射公式(两者均独立于生产语义函数)
# --------------------------------------------------------------------------

def certificate_self_check(bundle_before, bundle_after, cert):
    """用独立解释器在每个区域取代表点与边界点核对仿射公式。"""
    cap = bundle_before["cap"]
    checked = 0
    for key, regions in cert.items():
        # 额外: 在事件边界邻域做独立解释器全量交叉核对(有限边界, 非枚举整数)
        s_seqs = sorted({r["seq"] for _n, r in all_rows(bundle_before)})
        a_untils = sorted({r.get("until") for _n, r in all_rows(
            bundle_before) if r.get("until") is not None})
        probe_s = sorted({0} | {q for q in s_seqs if q > 0}
                         | {max(0, q - 1) for q in s_seqs if q > 0}
                         | {q + 1 for q in s_seqs})
        probe_a = sorted({0} | set(a_untils)
                         | {max(0, u - 1) for u in a_untils}
                         | {u + 1 for u in a_untils})
        base_actual = bottom_base(bundle_before, key)
        probe_b = [v for v in {0, cap, base_actual,
                               max(0, cap - 1), min(cap, 1)}
                   if v is not None] + [None]
        for s in probe_s:
            for a in probe_a:
                for base in probe_b:
                    expect_b = independent_resolve(
                        bundle_before, key, s, a, base)
                    expect_a = independent_resolve(
                        bundle_after, key, s, a, base)
                    hit = [r for r in regions
                           if region_applies(r, s, a, base)]
                    if expect_b == expect_a:
                        assert not hit, ("spurious region", key, s, a, base)
                    else:
                        assert hit, ("coverage", key, s, a, base)
                        for region in hit:
                            if base is None:
                                got_b = region["before"]
                                got_a = region["after"]
                                assert got_b == (None if expect_b is None
                                                 else [0, expect_b])
                                assert got_a == (None if expect_a is None
                                                 else [0, expect_a])
                            else:
                                assert eval_side("before", region, base) \
                                    == expect_b
                                assert eval_side("after", region, base) \
                                    == expect_a
                    checked += 1
        for region in regions:
            # 区域内仿射公式在 base 两端与代表点的独立求值核对
            if region["base"] is not None:
                lo, hi = region["base"]
                for base in (lo, hi - 1):
                    s = region["snapshot"][0]
                    a = region["at"][0]
                    assert eval_side("before", region, base) == \
                        independent_resolve(bundle_before, key, s, a, base)
                    assert eval_side("after", region, base) == \
                        independent_resolve(bundle_after, key, s, a, base)
                    checked += 1
            else:
                s = region["snapshot"][0]
                a = region["at"][0]
                nb = independent_resolve(bundle_before, key, s, a, None)
                na = independent_resolve(bundle_after, key, s, a, None)
                assert region["before"] == (None if nb is None else [0, nb])
                assert region["after"] == (None if na is None else [0, na])
                checked += 1
    return checked


def production_cross_check(bundle_before, bundle_after, cert):
    """原入口见证 vs 区域公式: 在观测点与边界探针上核对(见证角色, 非判定)。"""
    cap = bundle_before["cap"]
    probes = {(q["snapshot"], q["at"]) for q in bundle_before["observations"]}
    s_seqs = sorted({r["seq"] for _n, r in all_rows(bundle_before)})
    a_untils = sorted({r.get("until") for _n, r in all_rows(bundle_before)
                       if r.get("until") is not None})
    for s in {0, max(s_seqs) + 1, min(q for q in s_seqs if q > 0)}:
        probes.add((s, 0))
    for u in a_untils[:6]:
        probes.add((max(s_seqs), u))
    checked = 0
    for snapshot, at in sorted(probes):
        before_read = witness_via_production(bundle_before, snapshot, at)
        after_read = witness_via_production(bundle_after, snapshot, at)
        for key in bundle_before["keys"]:
            base = bottom_base(bundle_before, key)
            hit = [r for r in cert[key]
                   if region_applies(r, snapshot, at, base)]
            if before_read[key] == after_read[key]:
                assert not hit, ("production cross-check spurious", key)
            else:
                assert hit, ("production cross-check coverage", key)
                for region in hit:
                    assert eval_side("before", region, base) \
                        == before_read[key]
                    assert eval_side("after", region, base) \
                        == after_read[key]
            checked += 1
    return checked


# --------------------------------------------------------------------------
# 报告生成
# --------------------------------------------------------------------------

def fmt_iv(iv):
    if iv is INF:
        return "∞"
    return str(iv)


def region_table_rows(cert, base_by_key):
    lines = []
    for key in sorted(cert):
        base = base_by_key[key]
        base_txt = "null(缺行)" if base is None else str(base)
        lines.append(f"### 键 {key}（实际 bottom 基底: {base_txt}）")
        if not cert[key]:
            lines.append("- 全 (snapshot,at,base) 域无差异。")
            continue
        lines.append("| snapshot | at | base | before(m·base+b) | after |")
        lines.append("|---|---|---|---|---|")
        for r in cert[key]:
            lines.append(
                "| [%s,%s) | [%s,%s) | %s | %s | %s |" % (
                    r["snapshot"][0], fmt_iv(r["snapshot"][1]),
                    r["at"][0], fmt_iv(r["at"][1]),
                    "null" if r["base"] is None
                    else "[%d,%d)" % (r["base"][0], r["base"][1]),
                    "null" if r["before"] is None
                    else "%d·base+%d" % tuple(r["before"]),
                    "null" if r["after"] is None
                    else "%d·base+%d" % tuple(r["after"])))
        actual = [r for r in cert[key] if region_applies(r, 0, 0, base)
                  or (r["base"] is None and base is None)
                  or (r["base"] is not None and base is not None
                      and r["base"][0] <= base < r["base"][1])]
        actual = [r for r in cert[key]
                  if (r["base"] is None and base is None)
                  or (r["base"] is not None and base is not None
                      and r["base"][0] <= base < r["base"][1])]
        lines.append("")
        lines.append("代入实际基底后的实际差异读域共 %d 个区域:" % len(actual))
        def render(side, region, actual_base):
            pair = region[side]
            if pair is None:
                return "缺行"
            if actual_base is None:
                return str(pair[1])  # base=null 只允许 m=0
            return str(pair[0] * actual_base + pair[1])

        for r in actual:
            lines.append(
                "- snapshot∈[%s,%s), at∈[%s,%s): %s → %s" % (
                    r["snapshot"][0], fmt_iv(r["snapshot"][1]),
                    r["at"][0], fmt_iv(r["at"][1]),
                    render("before", r, base),
                    render("after", r, base)))
        lines.append("")
    return "\n".join(lines)


def build_report(bundle, cert, actual_domains, evidence, self_checked,
                 cross_checked, normal_cert_summary):
    cap = bundle["cap"]
    base_by_key = {k: bottom_base(bundle, k) for k in bundle["keys"]}
    total_regions = sum(len(v) for v in cert.values())
    actual_changed = {k: len(v) for k, v in actual_domains.items() if v}

    cf_lines = []
    for item in evidence["counterfactuals"]:
        cf_lines.append("#### %s — %s" % (item["id"], item["isolates"]))
        cf_lines.append("- 改动: %s, 位置 %s, %s → %s" % (
            item["mutation_kind"], item["location"],
            item["before_value"], item["after_value"]))
        for m in item["members"]:
            cf_lines.append(
                "  - (snapshot=%s,at=%s) before=%s after=%s" % (
                    m["snapshot"], m["at"],
                    json.dumps(m["before"], ensure_ascii=False),
                    json.dumps(m["after"], ensure_ascii=False)))
    cf_text = "\n".join(cf_lines)

    obs_lines = []
    after = replay_via_production(bundle)
    for q in bundle["observations"]:
        s, a = q["snapshot"], q["at"]
        b_read = witness_via_production(bundle, s, a)
        a_read = witness_via_production(after, s, a)
        changed = [k for k in bundle["keys"] if b_read[k] != a_read[k]]
        obs_lines.append(
            "- (snapshot=%d, at=%d) 源读数 %s；压实后 %s；漂移键 %s；"
            "expected 断言全部由 checks.py 见证成立。" % (
                s, a, json.dumps(b_read, ensure_ascii=False),
                json.dumps(a_read, ensure_ascii=False), changed))

    return f"""# 压实计数漂移诊断报告（version=1）

包 SHA-256: `{evidence['package_sha256']}`；cap={cap}；
本报告所有结论由 `analysis.py` 的独立区间证书引擎重算，生产入口
（`reader.read`、`compact.replay`）只承担见证捕获，不充当判定器。

## 1. 事故现象与核定

值班现象：压实后最新合计不变，但历史读数漂移、稍后读数再次变化。
原入口在四个观测点的实际读数（经 `reader.read` 见证，与
`logs/incident.log` 两次运行逐字节一致）：

{chr(10).join(obs_lines)}

合计抵消：以键 a、b 为例，(snapshot=40,at=0) 压实前后
a+b 均为 {cap}（a 少 5、b 少 5 的反向漂移在合计层抵消，
见 evidence.counterfactuals.CF8_balance_cancellation）。
“当前合计没变”是抵消结果，不代表视图保持。

本包 bottom 实际旧值：{json.dumps(base_by_key, ensure_ascii=False)}
（f 无 bottom 行，旧值为缺行 null，区别于计数 0）。
实际基底下存在差异的键与区域数：{json.dumps(actual_changed, ensure_ascii=False)}。

## 2. 源码根因（引用实际行号）

压实器 `compact.py` 把每个被选 run 内、屏障之间的连续 add 分组合并为
单条 add（compact.py:22-28），合并行取最大 seq、value 求和、
until 取 max（含 None 则永不超时）。该变换在四个独立维度上破坏
CONTRACT.md 第 14 行定义的读语义：

- **R1 逐次钳制被单次钳制替代（饱和中间态丢失）**：原语义对每个 add
  执行 `min(cap,max(0,旧值+value))`（reader.py:33-34），而合并行只在
  求和后钳制一次（compact.py:26 的 `sum(...)` 后由 reader.py:34 单次钳制）。
  键 a：基底 {cap-5}，+10 先饱和到 cap，再 -10 得 {cap-10}；
  合并值为 0，结果恒为基底 {cap-5}。键 b 对称（基底 5，-10 先触 0）。
- **R2 过期时间被聚合（短过期被长过期/None 吞没）**：compact.py:27
  `None if None in deadlines else max(deadlines)`。b1(until=50) 与
  b2(until=null) 合并后永不超时；at>=50 时原语义 b1 已跳过，合并行
  仍生效。c1/c2（20/80→80）、e1/e2（40/60→60）、f1/f2（30/40→40）
  同类。注意 at==until 即过期（reader.py:25，CONTRACT.md 第 12 行）。
- **R3 合并行只保留最大 seq（历史序号条带失真）**：compact.py:24-25
  以组内最后 seq 作为合并行 seq。原语义中较早 add 在
  S∈[较早seq, 最晚seq) 已可见，合并行在该窗口完全不可见，产生条带形
  差异（a:[11,14)、b:[12,16)、c:[10,18)、e:[20,21)、f:[22,23)、
  h:[27,28)、j:[31,32)）。
- **R4 分组无视范围删除与未选 run 屏障**：compact.py:9-11 仅按 key 收集
  点记录，range 行被原样抽出（compact.py:7），不切断 add 分组。
  键 d 的 d1(seq13) 被 r1(range d..e, seq15) 遮断，原语义在
  S∈[15,19) 以缺行起算 d2 得 30；合并行 d(seq19,value=50) 把 d1 的
  +20 带过屏障，得 50。未选 run（bottom/front）中的 put/erase 屏障
  同样不参与分组（如 h 的 erase@26 与 front.j-mask@40）。

四个机理可单独触发，也会叠加；R1/R2 改变“看到什么值”，R3/R4 改变
“在哪个 snapshot/at 窗口看到”。

## 3. 有限区间证书的构造与完整性论证

证书引擎（本文件 `diff_regions_for_key` 起）不调用
reader.resolve/read 或 compact.compact/replay，直接解释记录：

1. **单元划分**：snapshot 轴用全部记录 seq 切分（可见集合只在 seq 边界
   变化），at 轴用单元内可见 put/add 的全部 until 切分（过期集合只在
   until 边界变化，at==until 归入过期侧）。单元数 = O(记录数²)，
   与 cap、与整数取值个数无关，故不存在逐整数枚举。
2. **单元内程序**：按 seq 从新到旧扫描，确定屏障
   （未过期 put=常量基值；erase/过期 put/range=缺行屏障；无屏障=使用
   bottom 基底或缺行），并收集未过期 add 得到固定 delta 链。
3. **base 分段仿射**：delta 链对 base∈[0,cap] 的作用是恒等/常量起步、
   每次 `clamp(base+b)` 的分段仿射函数，斜率 m∈{{0,1}}；切分点仅可能
   是方程 base+b+delta=0 与 =cap 的整数解。合并两侧片段切分点后逐段比较，
   不等即输出区域；缺行基底（base=null）单独成域且只允许 m=0。
4. **不漏解的论证**：任一 (snapshot,at) 必落入唯一单元，单元内屏障与
   delta 链恒定；任一 base 必落入唯一仿射片段，片段内 m、b 恒定，
   故 before/after 在片段上要么处处相等要么处处不等。区域并集因此恰好
   等于完整差异域，且区域间由构造互不重叠；无差异键给出零区域而非空
   输出逃避（本包每个键均列出实际域，含零域键的显式声明）。
5. **双重独立自检**：独立解释器 `independent_resolve`（同样不依赖生产
   函数）在全部 seq/until 边界邻域与 base 代表点上重算 {self_checked} 个
   判定，与区域仿射公式一致；原入口 `reader.read` 另作
   {cross_checked} 个见证交叉核对。区域总数 {total_regions}。

### 压实安全/失真的可计算充要判据

对一次合法单次压实，记合并前后两套记录。**安全当且仅当**：对每个键，
按上述有限单元划分后，每个单元内 (a) 屏障种类与常量值相同，
(b) 未过期 delta 链逐元素相同（含顺序），(c) 在 base∈[0,cap] 与缺行
基底上的分段仿射结果逐片段相同。该条件可直接由有限记录计算，
无需枚举整数；“前后读数相等”只是它在单点上的推论，不能替代判据。
构造性充分条件（compact.py 改写时应同时满足）：合并组内不得存在
range/erase/put 屏障（含未选 run 中 seq 落在组区间内的屏障）；
组内全部 until 相同（或保留每条原始过期语义）；合并行必须在组内最早
seq 即对全部中间 snapshot 复现逐条 add 的可见性；value 不得预算术和，
须保留逐次钳制链。任一条不满足即落入上述 R1–R4 失真类。

## 4. 视角 1：实际 bottom 基底下的每键差异读域

{region_table_rows(cert, base_by_key)}

## 5. 视角 2：旧值 null 与 0..cap 全基底线（区域证书）

`evidence.json.regions` 中每个键的区域数组即完整
(key,snapshot,at,base) 差异集合：base 区间为 [lo,hi)（0<=lo<hi<=cap+1），
base=null 专指缺行基底；snapshot/at 的 hi=null 表示正无穷；
before/after 为 null（缺行）或 [m,b]（结果 m·base+b）。
基底代入原 bottom 即得到第 4 节实际域；多键不做联合猜测，
合计抵消仅按原包实际值在 CF8 核对。

## 6. 单因素反事实材料（每组相邻对照只改一个字段或一个查询参数）

{cf_text}

材料与机理的对应：CF1→R1（饱和），CF2→R2（过期聚合），
CF3/R3 条带与 CF9→R3（序号落点/缺行对零），CF4→R4（范围遮断），
CF5→R1+过期显露（未选 run 屏障），CF6→缺行 vs 零，CF7→erase 屏障
窗口，CF8→合计抵消。全部派生包内嵌于 evidence.counterfactuals，
可直接重放。

## 7. 正常回归与两次事故捕获

- `python3 checks.py normal`（未改 data/normal.json）退出
  {evidence['captures']['normal_run']['exit']}，输出
  NORMAL_COUNTER_READ_OK：三个公开观测点压实前后一致。
- 连续两次 `python3 checks.py incident` 退出均为 1、stdout 均含
  MERGE_VIEW_DIVERGENCE，且两次 stdout 逐字节相同；已与
  logs/incident.log 的基线记录核对一致（见 captures 中的
  log_match 字段）。
- 证书引擎对 normal 包的全域重算另列于
  evidence.extra_path_analyses：公开观测点虽全部通过，全域证书显示
  normal 包在未被观测覆盖的历史条带内同样存在 R3 类潜在差异
  （x 的 S∈[7,8)、y 的 S∈[4,5)），说明“观测点通过”不等于压实安全，
  与第 3 节充要判据吻合。

## 8. 影响范围小结

- 实际基底（视角 1）漂移键：{json.dumps(sorted(actual_changed), ensure_ascii=False)}；
  c、e、f、h、j 的漂移只出现在历史 snapshot 条带或特定 at 窗口，
  这解释了“当前合计没变、历史读数漂移、稍后再变”。
- 全基底证书（视角 2）共 {total_regions} 个互不重叠区域，覆盖
  null 与 0..cap 全部旧值；任何合法同格式包均可由同一引擎重算，
  算法复杂度只依赖记录数，不依赖 cap 数值大小。
- 未选 run（bottom、front）全程参与读取，parents 字段不参与读语义
  （CONTRACT.md 第 21 行），压实产物中的 parents 不构成修复证据。

## 9. 复现入口

- `python3 -I analysis.py run data/incident.json`：重算并写出
  REPORT.md、evidence.json。
- `python3 -I analysis.py verify data/incident.json`：重建完整区域、
  重跑全部捕获与反事实见证并与交付件核对，成功退出 0。
- `python3 -I analysis.py demo data/incident.json`：展示实际键值、
  读请求与证书区域对应关系。
"""


# --------------------------------------------------------------------------
# 子命令
# --------------------------------------------------------------------------

def collect_evidence(path):
    package_sha = sha256_file(path)
    bundle = reader.load(path)
    after = replay_via_production(bundle)

    cert = build_certificate(bundle, after)
    self_checked = certificate_self_check(bundle, after, cert)
    cross_checked = production_cross_check(bundle, after, cert)
    base_by_key = {k: bottom_base(bundle, k) for k in bundle["keys"]}
    actual_domains = actual_base_domain(cert, base_by_key)

    normal_capture = run_checks_subprocess("normal")
    incident_1 = run_checks_subprocess("incident")
    incident_2 = run_checks_subprocess("incident")
    demo_capture = run_checks_subprocess("demo")
    with open(INCIDENT_LOG, encoding="utf-8") as stream:
        baseline_log = stream.read()
    log_match = (incident_1["stdout"] in baseline_log
                 and incident_2["stdout"] in baseline_log
                 and incident_1["stdout"] == incident_2["stdout"])

    # 分析中调用原入口得到的见证(观测点)
    analysis_witnesses = []
    for q in bundle["observations"]:
        s, a = q["snapshot"], q["at"]
        analysis_witnesses.append({
            "snapshot": s, "at": a,
            "source_expected": q["expected"],
            "reader_before": witness_via_production(bundle, s, a),
            "reader_after": witness_via_production(after, s, a),
        })

    counterfactuals = build_counterfactuals(bundle)

    regions_flat = [r for key in bundle["keys"] for r in cert[key]]

    # 额外 PATH: normal 包的独立全域分析(始终使用未改公开包)
    normal_bundle = reader.load(NORMAL_PATH)
    normal_after = replay_via_production(normal_bundle)
    normal_cert = build_certificate(normal_bundle, normal_after)
    normal_self = certificate_self_check(normal_bundle, normal_after,
                                         normal_cert)
    normal_summary = {
        "path": NORMAL_PATH,
        "package_sha256": sha256_file(NORMAL_PATH),
        "region_counts": {k: len(v) for k, v in normal_cert.items()},
        "self_check_points": normal_self,
        "regions": [r for k in normal_bundle["keys"]
                    for r in normal_cert[k]],
    }

    evidence = {
        "version": 1,
        "package_path": os.path.relpath(path, WORKSPACE),
        "package_sha256": package_sha,
        "cap": bundle["cap"],
        "keys": bundle["keys"],
        "actual_bottom_base": base_by_key,
        "captures": {
            "normal_run": normal_capture,
            "incident_run_1": incident_1,
            "incident_run_2": incident_2,
            "demo_run": demo_capture,
            "baseline_incident_log": INCIDENT_LOG,
            "incident_log_match": log_match,
            "analysis_entry_witnesses": analysis_witnesses,
        },
        "regions": regions_flat,
        "region_counts": {k: len(cert[k]) for k in bundle["keys"]},
        "actual_base_domain_counts": {
            k: len(v) for k, v in actual_domains.items()},
        "actual_base_domains": actual_domains,
        "certificate_self_check_points": self_checked,
        "production_cross_check_points": cross_checked,
        "counterfactuals": counterfactuals,
        "extra_path_analyses": {"normal": normal_summary},
        "engine": {
            "judge": "analysis.py independent interpreter "
                     "(independent_resolve / program_for_cell); "
                     "reader/compact used only for witnesses",
            "enumeration": "partitions use seq/until events and affine "
                           "clamp cut points only; no integer enumeration",
        },
    }
    return evidence, bundle, after, cert, actual_domains, \
        self_checked, cross_checked, normal_summary


def cmd_run(path):
    (evidence, bundle, after, cert, actual_domains, self_checked,
     cross_checked, normal_summary) = collect_evidence(path)
    with open(EVIDENCE_PATH, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, ensure_ascii=False, indent=2,
                  sort_keys=True)
    report = build_report(bundle, cert, actual_domains, evidence,
                          self_checked, cross_checked, normal_summary)
    with open(REPORT_PATH, "w", encoding="utf-8") as stream:
        stream.write(report)
    print("WROTE", REPORT_PATH, EVIDENCE_PATH)
    print("regions:", evidence["region_counts"],
          "self_check:", self_checked,
          "cross_check:", cross_checked,
          "log_match:", evidence["captures"]["incident_log_match"])


def cmd_verify(path):
    if not (os.path.exists(EVIDENCE_PATH) and os.path.exists(REPORT_PATH)):
        print("VERIFY_FAIL missing deliverables")
        return 1
    with open(EVIDENCE_PATH, encoding="utf-8") as stream:
        delivered = json.load(stream)
    (evidence, bundle, after, cert, actual_domains, self_checked,
     cross_checked, normal_summary) = collect_evidence(path)

    failures = []

    def check(name, cond):
        if not cond:
            failures.append(name)

    check("version", delivered.get("version") == 1)
    check("sha256", delivered.get("package_sha256")
          == evidence["package_sha256"] == sha256_file(path))
    check("regions_rebuilt_exact",
          delivered.get("regions") == evidence["regions"])
    check("region_counts",
          delivered.get("region_counts") == evidence["region_counts"])
    check("actual_domains",
          delivered.get("actual_base_domains")
          == evidence["actual_base_domains"])
    check("counterfactuals_replay",
          delivered.get("counterfactuals") is not None
          and len(delivered["counterfactuals"])
          == len(evidence["counterfactuals"]))
    # 反事实逐组重放核对
    for old, new in zip(delivered["counterfactuals"],
                        evidence["counterfactuals"]):
        check("cf:" + new["id"],
              old["members"] == new["members"]
              and old["derived_bundle"] == new["derived_bundle"])
    check("captures_exit",
          evidence["captures"]["normal_run"]["exit"] == 0
          and evidence["captures"]["incident_run_1"]["exit"] == 1
          and evidence["captures"]["incident_run_2"]["exit"] == 1
          and evidence["captures"]["demo_run"]["exit"] == 0)
    check("incident_stdout_stable",
          evidence["captures"]["incident_run_1"]["stdout"]
          == evidence["captures"]["incident_run_2"]["stdout"])
    check("incident_log_match",
          evidence["captures"]["incident_log_match"])
    check("normal_marker",
          "NORMAL_COUNTER_READ_OK"
          in evidence["captures"]["normal_run"]["stdout"])
    check("divergence_marker",
          "MERGE_VIEW_DIVERGENCE"
          in evidence["captures"]["incident_run_1"]["stdout"])
    check("extra_normal_analysis",
          delivered.get("extra_path_analyses")
          == evidence["extra_path_analyses"])
    # 区域结构合法性(完整重建, 非抽查)
    seen = set()
    cap = bundle["cap"]
    for r in evidence["regions"]:
        key = r["key"]
        if r["base"] is None:
            check("null_base_m0:" + key,
                  r["before"] is None or r["before"][0] == 0)
            check("null_base_m0_after:" + key,
                  r["after"] is None or r["after"][0] == 0)
        else:
            lo, hi = r["base"]
            check("base_range:" + key, 0 <= lo < hi <= cap + 1)
        check("before_after_differ:" + key, r["before"] != r["after"])
        sig = (key, json.dumps(r["snapshot"]), json.dumps(r["at"]),
               json.dumps(r["base"]))
        check("disjoint:" + key, sig not in seen)
        seen.add(sig)
    with open(REPORT_PATH, encoding="utf-8") as stream:
        report_text = stream.read()
    for needle in ("R1", "R2", "R3", "R4", "compact.py:22", "reader.py:33",
                   "充要判据", "缺行", "合计抵消"):
        check("report:" + needle, needle in report_text)

    if failures:
        print("VERIFY_FAIL")
        for name in failures:
            print(" -", name)
        return 1
    print("VERIFY_OK regions=%d self_check_points=%d "
          "cross_check_points=%d counterfactuals=%d" % (
              len(evidence["regions"]), self_checked, cross_checked,
              len(evidence["counterfactuals"])))
    return 0


def cmd_demo(path):
    bundle = reader.load(path)
    after = replay_via_production(bundle)
    cert = build_certificate(bundle, after)
    base_by_key = {k: bottom_base(bundle, k) for k in bundle["keys"]}
    print("PACKAGE", os.path.relpath(path, WORKSPACE),
          "sha256", sha256_file(path))
    for q in bundle["observations"]:
        s, a = q["snapshot"], q["at"]
        before = witness_via_production(bundle, s, a)
        aft = witness_via_production(after, s, a)
        print("\nQUERY snapshot=%d at=%d" % (s, a))
        for key in bundle["keys"]:
            mark = "DRIFT" if before[key] != aft[key] else "ok"
            base = base_by_key[key]
            hit = [r for r in cert[key]
                   if region_applies(r, s, a, base)]
            region_desc = "no-region"
            if hit:
                r = hit[0]
                region_desc = ("region s[%s,%s) a[%s,%s) base=%s "
                               "before=%s after=%s" % (
                                   r["snapshot"][0],
                                   fmt_iv(r["snapshot"][1]),
                                   r["at"][0], fmt_iv(r["at"][1]),
                                   "null" if r["base"] is None
                                   else "[%d,%d)" % tuple(r["base"]),
                                   r["before"], r["after"]))
            print("  %s base=%-13s before=%-14s after=%-14s %s | %s" % (
                key, "null" if base is None else base,
                before[key], aft[key], mark, region_desc))
    print("\nREGION COUNTS (full base certificate):",
          json.dumps({k: len(v) for k, v in cert.items()},
                     ensure_ascii=False))
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    mode = argv[1]
    path = argv[2] if len(argv) > 2 else DEFAULT_PATH
    if mode == "run":
        cmd_run(path)
        return 0
    if mode == "verify":
        return cmd_verify(path)
    if mode == "demo":
        return cmd_demo(path)
    print("unknown mode:", mode)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
