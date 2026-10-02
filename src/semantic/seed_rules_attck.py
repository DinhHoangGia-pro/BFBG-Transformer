"""
seed_rules_attck.py
====================
Bang luat seed (weak-supervision) cho Learnt Semantic Dependency Predictor,
thay the hoan toan Bang 1 (5 luat SWC co dinh) cua ban EVM/T-CFBG cu bang
5 ky thuat MITRE ATT&CK pho bien o malware ngan hang (Trickbot va cac ho
lien quan), da chot o ke hoach pivot (BFBG-Transformer).

BAI HOC BAT BUOC PHAI NHO (xem docs/LESSONS_FROM_EVM_CODEBASE.md):
  Ban EVM cu dinh nghia luat seed yeu cau 2 opcode NAM NGAY CANH NHAU trong
  instruction stream -> 2/5 luat quan trong nhat gan nhu KHONG BAO GIO khop
  du lieu that (0,07% va 0% tren 5.797 hop dong). De KHONG LAP LAI loi nay,
  moi luat khop theo CUA SO (window) tren chuoi cac loi goi API DA RESOLVE,
  khong doi hoi lien ke tuyet doi.

SUA LAN 2 (sau khi review code phat hien them mot bien the khac cua chinh
loi tren, truoc ca khi chay check_seed_rule_fire_rate.py tren du lieu
that): mot vai ky thuat (persistence T1547, anti-analysis T1497) THUONG
CHI CAN MOT lenh goi API DUY NHAT la du bang chung (vi du: mot
CreateServiceW duy nhat DA LA persistence that su, khong can lenh goi thu
2 cung ho di kem). Yeu cau ">=2 API dong xuat hien" cho cac ky thuat nay la
mot gia dinh sai tren giay, dung kieu voi loi "lien ke tuyet doi" cua ban
EVM - chi khac la lan nay bat duoc o buoc review code, truoc khi kip thanh
mot con so 0% am tham trong bao cao.

SUA: tach rieng hai loai tin hieu:
  - SeedEdge (quan he CAP node, bat buoc >=2 dau) - dung cho T1055 (chuoi
    bat buoc nhieu buoc) va cho truong hop T1547/T1497/T1071 khi THAT SU
    co >=2 API dong xuat hien gan nhau (bang chung manh hon).
  - NodeIndicator (co moi NODE DON LE, khong can quan he) - dung cho
    T1547/T1497/T1071 khi chi co MOT lenh goi don le - thay vi am tham bo
    qua (nhu ban dau), gan co truc tiep vao node do de dua vao vector dac
    trung node khi GNN hoc bieu dien, khong ep thanh edge gia.
  T1055 (ordered chain) KHONG tao NodeIndicator tu buoc le, vi mot buoc
  don le trong chain nay (vi du chi co "OpenProcess") la API cuc ky pho
  bien o phan mem hop phap, gan co rieng le se qua nhieu nhieu.

Pham vi khop VAN CHI TRONG 1 HAM (function) - day la gioi han CO CHU DICH,
khong phai loi: kien truc da co san Stage 2 (Macro Inter-function Graph
Transformer) chiu trach nhiem lan truyen tin hieu XUYEN HAM; tang nay
(micro-level Esem/NodeIndicator) chi lo quan he TRONG MOT HAM. Neu sau nay
du lieu that cho thay can mo rong cua so xuyen ham (vi du chuoi process-
injection bi tach qua 1 ham wrapper), day la huong mo rong o bfbg_builder
(noi thuc su co call-graph de biet ham nao goi ham nao), KHONG sua o day.

CHUAN HOA TEN API (vi du "kernel32.dll!OpenProcess" -> "OpenProcess") LA
TRACH NHIEM CUA bfbg_builder.py, KHONG PHAI cua file nay. ResolvedCall.api_name
o day LUON duoc gia dinh la ten DA CHUAN HOA (khong con tien to DLL,
khong phan biet hoa/thuong ngoai y). Neu bfbg_builder truyen vao ten chua
chuan hoa, moi luat trong file nay se khong khop - day la dau hieu de phat
hien loi o lop resolve, khong phai o lop nay.

Sau khi tich hop vao bfbg_builder.py, BAT BUOC chay
experiments/qa/check_seed_rule_fire_rate.py truoc khi tin tuong bat ky
luat nao trong bang nay - dung gia dinh mot luat "nhin hop ly" la no se
khop du lieu that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# 1. Cau truc du lieu dau vao / dau ra
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolvedCall:
    """Mot loi goi API DA CHUAN HOA TEN (khong con tien to DLL, vi du
    "OpenProcess" chu khong phai "kernel32.dll!OpenProcess") va DA DUOC
    GAN VOI 1 NODE trong BFBG. Viec chuan hoa ten la trach nhiem cua
    bfbg_builder.py, khong phai cua module nay.

    node_id  : id node trong do thi.
    api_name : ten ham DA CHUAN HOA.
    position : thu tu goi ham THEO VI TRI THUC TE trong ham (int, khong
               phai string) - dung de tinh khoang cach cua so.
    """
    node_id: str
    api_name: str
    position: int


@dataclass(frozen=True)
class SeedEdge:
    """Mot canh ngu nghia (weak-supervision) - tuong duong seed_sem_edges
    trong ban EVM cu, nhung gan voi node_id thay vi opcode-index. BAT BUOC
    co 2 dau (src/dst) - khong dung cho bang chung tu 1 node don le."""
    src_node_id: str
    dst_node_id: str
    technique_id: str      # vi du "T1055"
    rule_name: str         # vi du "process_injection"
    confidence: str        # "full_chain" | "partial_chain" | "co_occurrence" | "cross_function_1hop"


@dataclass(frozen=True)
class NodeIndicator:
    """Co bang chung CAP NODE DON LE (khong can quan he voi node khac) -
    dung cho cac ky thuat ma MOT lenh goi API da du la bang chung (vi du:
    mot CreateServiceW duy nhat da la persistence). Dua truc tiep vao
    vector dac trung cua node o tang Token-Sequence Transformer, KHONG di
    qua Learnt Semantic Dependency Predictor (vi khong phai quan he cap)."""
    node_id: str
    technique_id: str
    rule_name: str


class MatchMode(str, Enum):
    ORDERED_CHAIN = "ordered_chain"      # T1055: thu tu bat buoc
    ANY_ORDER_SET = "any_order_set"      # T1547, T1497: khong can thu tu
    FAMILY_SEQUENCE = "family_sequence"  # T1071: cung ho API


# ---------------------------------------------------------------------------
# 2. Bang 5 luat seed ATT&CK (thay Bang 1 SWC cu)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SeedRule:
    technique_id: str
    name: str
    description: str
    mode: MatchMode
    apis: tuple[str, ...] = field(default_factory=tuple)
    min_chain_length: int = 2
    family_prefixes: tuple[str, ...] = field(default_factory=tuple)
    singleton_as_node_indicator: bool = True
    # True: khi CHI co 1 API khop (khong du de tao edge), van gan
    #   NodeIndicator thay vi bo qua hoan toan. Dat False cho T1055 vi mot
    #   buoc le trong ordered-chain la API qua pho bien de tin cay rieng le.
    training_caveat: str = ""
    # Metadata (KHONG anh huong output cua generate_seed_edges /
    #   generate_cross_function_seed_edges). Khac rong = luat nay co han che
    #   DA XAC NHAN khi dung lam tin hieu huan luyen; cac buoc sau
    #   (check_label_confidence, dataset loader) doc de loc/canh bao neu can.


ATTACK_SEED_RULES: tuple[SeedRule, ...] = (
    SeedRule(
        technique_id="T1055",
        name="process_injection",
        description=(
            "OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> "
            "CreateRemoteThread. Chuoi kinh dien nhat cua ho banking-trojan "
            "de chiem quyen mot process hop phap."
        ),
        mode=MatchMode.ORDERED_CHAIN,
        apis=(
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ),
        min_chain_length=2,
        singleton_as_node_indicator=False,
        # FP DA XAC NHAN: fixture benign self_patch_updater.exe (self-injection
        # hop phap) khien ca intra-function lan cross_function_seed_edges fire
        # du 4 buoc. Luat chi khop theo ten API + thu tu + khoang cach, KHONG
        # doc tham so OpenProcess de phan biet tien trinh dich la chinh no hay
        # tien trinh khac. Xem docs/LESSONS_LEARNED.md.
        training_caveat="api_call_only - khong phan biet tu-tiem voi "
                        "tiem-tien-trinh-khac, CAN than khi dung lam tin hieu huan luyen",
    ),
    SeedRule(
        technique_id="T1547",
        name="persistence",
        description=(
            "RegSetValueExW/A hoac CreateServiceW/A. MOT lenh goi duy nhat "
            "DA LA bang chung persistence - khong doi hoi lenh thu hai."
        ),
        mode=MatchMode.ANY_ORDER_SET,
        apis=(
            "RegSetValueExW",
            "RegSetValueExA",
            "CreateServiceW",
            "CreateServiceA",
        ),
    ),
    SeedRule(
        technique_id="T1071",
        name="c2_communication",
        description=(
            "Chuoi loi goi trong ho API mang (WinINet hoac WinHTTP) - dau "
            "hieu giao tiep C2 qua HTTP(S). >=2 lan goi -> edge; 1 lan goi "
            "-> van gan NodeIndicator (bang chung yeu hon nhung khong bo qua)."
        ),
        mode=MatchMode.FAMILY_SEQUENCE,
        family_prefixes=("Internet", "WinHttp"),
    ),
    SeedRule(
        technique_id="T1497",
        name="anti_analysis",
        description=(
            "IsDebuggerPresent / CheckRemoteDebuggerPresent / "
            "NtQueryInformationProcess. MOT lenh goi duy nhat DA LA bang "
            "chung - day la ky thuat ma Claude Code phat hien dung: ban "
            "truoc bo qua oan cac mau chi goi 1 lan."
        ),
        mode=MatchMode.ANY_ORDER_SET,
        apis=(
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        ),
    ),
)

DEFAULT_WINDOW_SIZE = 8
# Da dua vao configs/model.yaml (semantic.window_size) - giu nguyen, khong
# can go ra: bfbg_builder se doc tu config nay thay vi dung mac dinh o day.


# ---------------------------------------------------------------------------
# 3. Ham khop luat - sinh seed edges + node indicators tu 1 chuoi
#    ResolvedCall (trong 1 ham)
# ---------------------------------------------------------------------------

def _within_window(pos_a: int, pos_b: int, window_size: int) -> bool:
    return abs(pos_a - pos_b) <= window_size


def _match_ordered_chain(
    calls: Sequence[ResolvedCall], rule: SeedRule, window_size: int
) -> list[SeedEdge]:
    api_to_calls: dict[str, list[ResolvedCall]] = {}
    for c in calls:
        api_to_calls.setdefault(c.api_name, []).append(c)

    chain_nodes: list[ResolvedCall] = []
    cursor_pos = float("-inf")
    for api_name in rule.apis:
        candidates = [c for c in api_to_calls.get(api_name, []) if c.position > cursor_pos]
        if not candidates:
            break
        nxt = min(candidates, key=lambda c: c.position)
        if chain_nodes and not _within_window(chain_nodes[-1].position, nxt.position, window_size):
            break
        chain_nodes.append(nxt)
        cursor_pos = nxt.position

    if len(chain_nodes) < rule.min_chain_length:
        return []

    confidence = "full_chain" if len(chain_nodes) == len(rule.apis) else "partial_chain"
    return [
        SeedEdge(a.node_id, b.node_id, rule.technique_id, rule.name, confidence)
        for a, b in zip(chain_nodes, chain_nodes[1:])
    ]


def _matched_calls_for_set(calls: Sequence[ResolvedCall], apis: tuple[str, ...]) -> list[ResolvedCall]:
    return sorted((c for c in calls if c.api_name in apis), key=lambda c: c.position)


def _matched_calls_for_family(calls: Sequence[ResolvedCall], prefixes: tuple[str, ...]) -> list[ResolvedCall]:
    def in_family(api_name: str) -> bool:
        return any(api_name.startswith(p) for p in prefixes)
    return sorted((c for c in calls if in_family(c.api_name)), key=lambda c: c.position)


def _match_any_order_set(
    calls: Sequence[ResolvedCall], rule: SeedRule, window_size: int
) -> tuple[list[SeedEdge], list[NodeIndicator]]:
    matched = _matched_calls_for_set(calls, rule.apis)
    return _pairs_or_singletons(matched, rule, window_size)


def _match_family_sequence(
    calls: Sequence[ResolvedCall], rule: SeedRule, window_size: int
) -> tuple[list[SeedEdge], list[NodeIndicator]]:
    matched = _matched_calls_for_family(calls, rule.family_prefixes)
    return _pairs_or_singletons(matched, rule, window_size)


def _pairs_or_singletons(
    matched: list[ResolvedCall], rule: SeedRule, window_size: int
) -> tuple[list[SeedEdge], list[NodeIndicator]]:
    """Dung chung cho ANY_ORDER_SET va FAMILY_SEQUENCE: >=2 API trong cung
    window -> edge giua TUNG CAP lien tiep nam trong window; MOI call con
    lai khong ghep duoc voi ai trong window -> NodeIndicator (neu
    rule.singleton_as_node_indicator=True), thay vi bi am tham bo qua."""
    edges: list[SeedEdge] = []
    paired_ids: set[str] = set()
    for a, b in zip(matched, matched[1:]):
        if _within_window(a.position, b.position, window_size):
            edges.append(SeedEdge(a.node_id, b.node_id, rule.technique_id, rule.name, "co_occurrence"))
            paired_ids.add(a.node_id)
            paired_ids.add(b.node_id)

    indicators: list[NodeIndicator] = []
    if rule.singleton_as_node_indicator:
        for c in matched:
            if c.node_id not in paired_ids:
                indicators.append(NodeIndicator(c.node_id, rule.technique_id, rule.name))
    return edges, indicators


_PAIR_MATCHERS = {
    MatchMode.ANY_ORDER_SET: _match_any_order_set,
    MatchMode.FAMILY_SEQUENCE: _match_family_sequence,
}


def generate_seed_edges(
    calls: Sequence[ResolvedCall],
    window_size: int = DEFAULT_WINDOW_SIZE,
    rules: Iterable[SeedRule] = ATTACK_SEED_RULES,
) -> list[SeedEdge]:
    """Sinh SeedEdge cho ca 5 luat. Goi cung voi generate_node_indicators()
    de khong bo sot bang chung tu cac lenh goi don le (T1547/T1497/T1071)."""
    edges: list[SeedEdge] = []
    for rule in rules:
        if rule.mode is MatchMode.ORDERED_CHAIN:
            edges.extend(_match_ordered_chain(calls, rule, window_size))
        else:
            e, _ = _PAIR_MATCHERS[rule.mode](calls, rule, window_size)
            edges.extend(e)
    return edges


def generate_node_indicators(
    calls: Sequence[ResolvedCall],
    window_size: int = DEFAULT_WINDOW_SIZE,
    rules: Iterable[SeedRule] = ATTACK_SEED_RULES,
) -> list[NodeIndicator]:
    """Sinh NodeIndicator cho cac lenh goi KHONG ghep duoc thanh edge
    (chu yeu la cac truong hop chi co 1 API khop). T1055 khong tao
    indicator tu day (singleton_as_node_indicator=False)."""
    indicators: list[NodeIndicator] = []
    for rule in rules:
        if rule.mode is MatchMode.ORDERED_CHAIN:
            continue
        _, ind = _PAIR_MATCHERS[rule.mode](calls, rule, window_size)
        indicators.extend(ind)
    return indicators


# ---------------------------------------------------------------------------
# 3b. Khop LIEN HAM 1-hop qua call graph (Phuong an B, docs/LESSONS_LEARNED.md
#     muc 2) - chi cho ORDERED_CHAIN (hien chi T1055). KHONG thay the
#     generate_seed_edges(): ket qua la bang chung RIENG, confidence rieng.
# ---------------------------------------------------------------------------

def generate_cross_function_seed_edges(
    calls_by_function: dict[str, Sequence[ResolvedCall]],
    callgraph: Iterable[tuple[str, str]],
    window_size: int = DEFAULT_WINDOW_SIZE,
    rules: Iterable[SeedRule] = ATTACK_SEED_RULES,
) -> list[SeedEdge]:
    """Khop ORDERED_CHAIN qua ranh gioi 1 canh goi truc tiep: cac buoc dau
    cua chuoi o ham CHA, cac buoc sau o ham CON F.

    calls_by_function : function_id -> ResolvedCall cua ham do (position la
                        thu tu TRONG ham do, nhu generate_seed_edges nhan).
    callgraph         : cac canh (caller_id, callee_id) goi truc tiep.

    Voi moi ham F CHUA khop du chain trong chinh no (_match_ordered_chain
    tren rieng F khong ra full_chain), voi TUNG ham cha P goi truc tiep F
    (xet rieng tung cha, khong gop nhieu cha): khop chain tren chuoi noi
    calls[P] + calls[F]. Chi giu chain co it nhat 1 node o P VA it nhat 1
    node o F (chain nam tron trong 1 ham khong phai bang chung lien ham).
    Moi SeedEdge cua chain do co confidence="cross_function_1hop".
    """
    calls_by_function = {f: list(c) for f, c in calls_by_function.items()}
    parents: dict[str, set[str]] = {}
    for caller, callee in callgraph:
        if caller != callee:
            parents.setdefault(callee, set()).add(caller)

    edges: list[SeedEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for rule in rules:
        if rule.mode is not MatchMode.ORDERED_CHAIN:
            continue
        chain_apis = set(rule.apis)
        for f_id, f_calls in calls_by_function.items():
            if not any(c.api_name in chain_apis for c in f_calls):
                continue
            own = _match_ordered_chain(f_calls, rule, window_size)
            if own and own[0].confidence == "full_chain":
                continue
            for p_id in sorted(parents.get(f_id, ())):
                p_calls = calls_by_function.get(p_id, [])
                if not any(c.api_name in chain_apis for c in p_calls):
                    continue
                # GIA DINH HEURISTIC, CHUA XAC NHAN bang op_str/vi tri lenh call F
                # trong P (xem docs/LESSONS_LEARNED.md muc 2): MOI API-call cua cha
                # P duoc coi la XAY RA TRUOC moi API-call cua F. Thuc hien bang cach
                # doi position cua F len sau position lon nhat cua P; khoang cach
                # window qua ranh gioi ham = (so loi goi sau buoc cuoi o P) +
                # (position cua buoc dau o F) + 1.
                offset = max(c.position for c in p_calls) + 1
                f_shifted = [ResolvedCall(c.node_id, c.api_name, c.position + offset) for c in f_calls]
                chain = _match_ordered_chain(p_calls + f_shifted, rule, window_size)
                p_nodes = {c.node_id for c in p_calls}
                f_nodes = {c.node_id for c in f_calls}
                touched = {n for e in chain for n in (e.src_node_id, e.dst_node_id)}
                if not (touched & p_nodes and touched & f_nodes):
                    continue
                for e in chain:
                    key = (e.src_node_id, e.dst_node_id, e.technique_id)
                    if key not in seen:
                        seen.add(key)
                        edges.append(SeedEdge(e.src_node_id, e.dst_node_id, e.technique_id, e.rule_name,
                                              "cross_function_1hop"))
    return edges


# ---------------------------------------------------------------------------
# 4. T1027 (packing-indicator) - tin hieu CHUONG TRINH, khong phai node/edge
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StructuralIndicators:
    max_section_entropy: float
    has_import_table_anomaly: bool

    @property
    def is_likely_packed(self) -> bool:
        # Nguong 7.2 CHUA kiem chung tren du lieu that - xac nhan lai bang
        # experiments/qa/ truoc khi dung de bao cao ket qua chinh thuc.
        return self.max_section_entropy >= 7.2 or self.has_import_table_anomaly


def compute_structural_indicators(
    section_entropies: Sequence[float],
    import_table_anomaly: bool,
) -> StructuralIndicators:
    return StructuralIndicators(
        max_section_entropy=max(section_entropies) if section_entropies else 0.0,
        has_import_table_anomaly=import_table_anomaly,
    )


# ---------------------------------------------------------------------------
# 5. Smoke test thu cong - chay: python -m src.semantic.seed_rules_attck
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_calls = [
        ResolvedCall("n1", "OpenProcess", position=3),
        ResolvedCall("n2", "SomeUnrelatedCall", position=5),
        ResolvedCall("n3", "VirtualAllocEx", position=7),
        ResolvedCall("n4", "WriteProcessMemory", position=12),
        ResolvedCall("n5", "CreateRemoteThread", position=15),
        ResolvedCall("n6", "InternetOpenA", position=20),
        ResolvedCall("n7", "IsDebuggerPresent", position=30),   # mot lan duy nhat
        ResolvedCall("n8", "CreateServiceW", position=40),      # mot lan duy nhat
    ]
    print("=== SeedEdge ===")
    for e in generate_seed_edges(demo_calls, window_size=8):
        print(e)
    print("=== NodeIndicator (truoc day bi bo qua oan) ===")
    for i in generate_node_indicators(demo_calls, window_size=8):
        print(i)

    indicators = compute_structural_indicators(
        section_entropies=[6.1, 7.6, 5.0], import_table_anomaly=False
    )
    print(indicators, "-> is_likely_packed =", indicators.is_likely_packed)
