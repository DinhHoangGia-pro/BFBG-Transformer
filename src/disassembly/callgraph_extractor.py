"""
callgraph_extractor.py
======================
Do thi lien ham (G_inter) lay truc tiep tu callgraph cua angr
(cfg.kb.callgraph.edges()) - thay cho heuristic tu che tach "ham" theo
JUMPDEST cua ban EVM.

Node i = ham thu i trong LiftedBinary.functions (sap theo dia chi), nen chi
so canh khop truc tiep voi thu tu ham ma bfbg_builder dung.

Loi goi toi ham import (SimProcedure trong cle##externs, goi truc tiep qua
`call [IAT]` hoac qua thunk `jmp [IAT]`) KHONG thanh canh trong G_inter ma
duoc gom thanh danh sach API-call cua tung ham, dang "kernel32.dll!CreateProcessW"
- dau vao cho luat seed ATT&CK va feature num_api_calls.
"""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class CallGraph:
    func_addrs: list                                # node i -> dia chi ham
    edges: list = field(default_factory=list)       # (caller_idx, callee_idx), khong trung, co the tu goi
    api_calls: dict = field(default_factory=dict)   # dia chi ham -> [API, ...] moi call site 1 lan

    @property
    def num_api_calls(self):
        return sum(len(v) for v in self.api_calls.values())

    @property
    def unique_apis(self):
        return sorted({a for v in self.api_calls.values() for a in v})

    def edge_index(self):
        """Dang [[src...], [dst...]] cho PyG."""
        if not self.edges:
            return [[], []]
        src, dst = zip(*self.edges)
        return [list(src), list(dst)]

    def api_histogram(self):
        return Counter(a for v in self.api_calls.values() for a in v)


def api_name(func):
    dll = (func.binary_name or '?').lower()
    return f"{dll}!{func.name}"


def _resolve_apis(callee, functions, callgraph, depth=2):
    """API ma callee dai dien: chinh no neu la SimProcedure, hoac cac
    SimProcedure ma thunk (is_plt) nhay toi."""
    if callee.is_simprocedure:
        return [api_name(callee)]
    if callee.is_plt and depth > 0:
        apis = []
        for nxt in set(callgraph.successors(callee.addr)):
            if nxt in functions:
                apis.extend(_resolve_apis(functions[nxt], functions, callgraph, depth - 1))
        return apis
    return []


def extract_callgraph(lifted):
    """lifted: LiftedBinary tu pe_lifter.lift_pe(..., keep_project=True)."""
    if lifted.cfg is None:
        raise ValueError("LiftedBinary khong giu CFG - goi lift_pe(..., keep_project=True)")
    functions = lifted.cfg.kb.functions
    callgraph = lifted.cfg.kb.callgraph

    func_addrs = [f.addr for f in lifted.functions]
    index = {addr: i for i, addr in enumerate(func_addrs)}

    edges = set()
    api_calls = {}
    # MultiDiGraph: moi call site la 1 canh rieng (key khac nhau)
    for caller, callee, _key in callgraph.edges(keys=True):
        if caller not in index:
            continue
        if callee in index:
            edges.add((index[caller], index[callee]))
        elif callee in functions:
            apis = _resolve_apis(functions[callee], functions, callgraph)
            if apis:
                api_calls.setdefault(caller, []).extend(apis)

    return CallGraph(func_addrs=func_addrs, edges=sorted(edges), api_calls=api_calls)
