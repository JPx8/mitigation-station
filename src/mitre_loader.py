import json
from pathlib import Path
from typing import Optional

DATA_FILE = Path(__file__).parent.parent / "data" / "enterprise-attack.json"

class MITRELoader:
    def __init__(self, data_path=None):
        self.data_path = Path(data_path) if data_path else DATA_FILE
        self.techniques = {}
        self.by_name = {}
        self._stix_to_tid = {}
        self._loaded = False

    def load(self):
        if not self.data_path.exists():
            return False
        with open(self.data_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self._index(bundle)
        self._loaded = True
        return True

    def is_loaded(self):
        return self._loaded

    def _index(self, bundle):
        objects = bundle.get("objects", [])
        for obj in objects:
            if obj.get("type") != "attack-pattern": continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"): continue
            tid = self._ext_id(obj)
            if not tid: continue
            self._stix_to_tid[obj["id"]] = tid
            self.techniques[tid] = {
                "id": tid, "name": obj.get("name",""),
                "description": obj.get("description",""),
                "platforms": obj.get("x_mitre_platforms",[]),
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases",[])],
                "url": self._ext_url(obj), "detection": obj.get("x_mitre_detection",""),
                "mitigations": [],
            }
            self.by_name[obj["name"].lower()] = tid
        mitig = {o["id"]:o for o in objects if o.get("type")=="course-of-action" and not o.get("revoked")}
        for obj in objects:
            if obj.get("type")!="relationship" or obj.get("relationship_type")!="mitigates": continue
            src,tgt = obj.get("source_ref",""),obj.get("target_ref","")
            if src not in mitig: continue
            tid = self._stix_to_tid.get(tgt)
            if not tid: continue
            m = mitig[src]
            self.techniques[tid]["mitigations"].append({"id":self._ext_id(m) or "M????","name":m.get("name",""),"description":m.get("description","")})

    def _ext_id(self, obj):
        for r in obj.get("external_references",[]):
            if r.get("source_name")=="mitre-attack": return r.get("external_id")
    def _ext_url(self, obj):
        for r in obj.get("external_references",[]):
            if r.get("source_name")=="mitre-attack": return r.get("url","")
        return ""
    def get_technique(self, tid): return self.techniques.get(tid.upper())
    def search_by_name(self, name):
        n = name.lower()
        if n in self.by_name: return self.techniques[self.by_name[n]]
        for k,v in self.by_name.items():
            if n in k or k in n: return self.techniques[v]
    def get_techniques_for_tactic(self, tactic):
        t = tactic.lower().replace(" ","-")
        return [x for x in self.techniques.values() if t in x["tactics"]]
    def count(self): return len(self.techniques)
