import json, os, re
import anthropic

MODEL = "claude-sonnet-4-6"

EXTRACT_PROMPT = """You are a SOC analyst. Extract metadata and identify MITRE ATT&CK techniques from this alert.
Return ONLY valid JSON (no markdown):
{{"metadata":{{"user":"logged-in username","host":"device/hostname","timestamp":"incident date and time from alert body (not current time)"}},"threat_name":"specific malware/threat name or Unknown Threat","iocs":[{{"type":"sha256|md5|ip|domain|process|path","value":"exact IOC value"}}],"techniques":[{{"id":"T1059.001","name":"PowerShell","confidence":"high","rationale":"one sentence"}}],"summary":"executive summary","severity":"critical|high|medium|low","threat_actor_type":"nation-state|cybercriminal|insider|unknown"}}

Severity guidelines (use the alert's own severity label if present, otherwise infer):
- critical: active ransomware/destructive payload, confirmed data exfiltration, full domain compromise
- high: suspicious execution with C2 indicators, credential dumping, lateral movement detected
- medium: policy violations, anomalous but unconfirmed activity, single suspicious indicator
- low: informational, failed attempts, low-fidelity detections

Alert:
{alert_text}"""

MITIG_PROMPT = """For MITRE technique {technique_id} - {technique_name} on {platforms}, generate remediation checklist.
Return ONLY valid JSON:
{{"immediate_actions":["Step 1"],"short_term":["Within 24h"],"long_term":["Policy"],"detection_rules":["KQL snippet"],"references":["https://attack.mitre.org/techniques/{technique_id}/"]}}"""

THREAT_INTEL_PROMPT = """You are a threat intelligence analyst. Provide intel on this specific threat.
Threat Name: {threat_name}
IOCs: {iocs}
Summary: {summary}
Return ONLY valid JSON:
{{"specific_remediation":["Threat-specific step tailored to THIS exact threat","Step 2"],"threat_background":"2-3 sentences: origin, actor group, campaigns","estimated_victims":"known scale e.g. Thousands globally","targeted_industries":["Healthcare","Finance"],"osint_links":[{{"title":"Source Name","url":"https://...","description":"what it covers"}}]}}"""

class ClaudeAnalyzer:
    def __init__(self, api_key=None):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key: raise ValueError("ANTHROPIC_API_KEY not set")
        self.client = anthropic.Anthropic(api_key=key)

    def extract_techniques(self, alert_text):
        r = self.client.messages.create(model=MODEL, max_tokens=2048,
            messages=[{"role":"user","content":EXTRACT_PROMPT.format(alert_text=alert_text)}])
        return self._parse(r.content[0].text.strip())

    def generate_mitigations(self, technique):
        r = self.client.messages.create(model=MODEL, max_tokens=2048,
            messages=[{"role":"user","content":MITIG_PROMPT.format(
                technique_id=technique.get("id",""), technique_name=technique.get("name",""),
                platforms=", ".join(technique.get("platforms",["Windows"])))}])
        return self._parse(r.content[0].text.strip())

    def generate_threat_intel(self, analysis):
        r = self.client.messages.create(model=MODEL, max_tokens=2048,
            messages=[{"role":"user","content":THREAT_INTEL_PROMPT.format(
                threat_name=analysis.get("threat_name","Unknown Threat"),
                iocs=json.dumps(analysis.get("iocs",[])[:10]),
                summary=analysis.get("summary",""))}])
        return self._parse(r.content[0].text.strip())

    def _parse(self, text):
        text = re.sub(r"^```(?:json)?\s*","",text); text = re.sub(r"\s*```$","",text)
        try: return json.loads(text)
        except:
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try: return json.loads(m.group())
                except: pass
            return {"error":"parse failed","raw":text[:300]}