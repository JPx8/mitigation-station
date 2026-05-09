import os, sys, json
from pathlib import Path
import streamlit as st
sys.path.insert(0, str(Path(__file__).parent))
from mitre_loader import MITRELoader
from claude_analyzer import ClaudeAnalyzer
from pdf_generator import PDFGenerator

EXAMPLE_ALERT = """Alert: Suspicious PowerShell Execution
Time: 2024-01-15 14:32:11 UTC
Host: WORKSTATION-042 | User: jsmith | Severity: High
PowerShell.exe spawned by winword.exe with -EncodedCommand
Connection to 192.168.100.55:4444
SHA256: 4a5d6f7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run""".strip()

CONF_ORDER = {"high":0,"medium":1,"low":2}
CONF_COLOR = {"high":"#dc3545","medium":"#e6a817","low":"#28a745"}
SEV_COLOR = {"critical":"#8B0000","high":"#dc3545","medium":"#e6a817","low":"#28a745"}
SECTION = "font-size:1.4em;font-weight:700;margin:24px 0 8px 0;"

@st.cache_resource(show_spinner="Loading MITRE ATT&CK data...")
def get_mitre():
    l = MITRELoader(); l.load(); return l

def badge(conf):
    color = CONF_COLOR.get(conf.lower(),"#6c757d")
    return (f"<span style='background-color:{color};color:white;padding:3px 10px;"
            f"border-radius:12px;font-size:0.8em;font-weight:bold;'>{conf.upper()}</span>")

def vt_lookup(val, itype, key):
    import requests
    try:
        t = itype.lower()
        if t in ("sha256","md5","sha1"):
            url=f"https://www.virustotal.com/api/v3/files/{val}"; gui=f"https://www.virustotal.com/gui/file/{val}"
        elif t=="ip":
            url=f"https://www.virustotal.com/api/v3/ip_addresses/{val}"; gui=f"https://www.virustotal.com/gui/ip-address/{val}"
        elif t=="domain":
            url=f"https://www.virustotal.com/api/v3/domains/{val}"; gui=f"https://www.virustotal.com/gui/domain/{val}"
        else:
            return {"gui":f"https://www.virustotal.com/gui/search/{val}"}
        r = requests.get(url,headers={"x-apikey":key},timeout=10)
        if r.status_code==200:
            stats=r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"malicious":stats.get("malicious",0),"total":sum(stats.values()),"gui":gui}
        return {"gui":gui}
    except: return None

def render_card(t, detail, mit):
    tid=t.get("id",""); tname=t.get("name",""); conf=t.get("confidence","unknown")
    color=CONF_COLOR.get(conf.lower(),"#6c757d")
    st.markdown(f"""<div style='border-left:5px solid {color};padding:10px 18px;
        background:rgba(255,255,255,0.04);border-radius:6px;margin:6px 0 0 0;'>
        <span style='font-weight:700;font-size:1em;color:{color};'>{tid}</span>
        <span style='font-weight:600;'> &mdash; {tname}</span>
        &nbsp;&nbsp;{badge(conf)}
    </div>""", unsafe_allow_html=True)
    with st.expander("Details / Remediation"):
        if t.get("rationale"): st.info(t["rationale"])
        c1,c2=st.columns(2)
        with c1:
            if detail:
                st.markdown(f"**Tactics:** {', '.join(detail.get('tactics',[]))}")
                st.markdown(f"**Platforms:** {', '.join(detail.get('platforms',[]))}")
                if detail.get("url"): st.markdown(f"[View on MITRE ATT&CK]({detail['url']})")
        with c2:
            if detail and detail.get("description"): st.caption(detail["description"][:300]+"...")
        if mit and "error" not in mit:
            st.markdown("---"); st.markdown("#### Remediation Checklist")
            for lbl,key in [("Immediate Actions","immediate_actions"),("Short-Term (24-48h)","short_term"),("Long-Term","long_term")]:
                items=mit.get(key,[])
                if items:
                    st.markdown(f"**{lbl}**")
                    for item in items: st.checkbox(item, key=f"chk_{tid}_{key}_{item[:20]}")
            for rule in mit.get("detection_rules",[]): st.code(rule,language="sql")
            for ref in mit.get("references",[]): st.markdown(f"- {ref}")

def main():
    st.set_page_config(page_title="Mitigation Station", layout="wide")
    with st.sidebar:
        st.title("Mitigation Station"); st.caption("MS Sentinel SOC Lab"); st.divider()
        _ant=os.environ.get("ANTHROPIC_API_KEY","")
        if _ant: st.success("Anthropic API key configured"); api_key=_ant
        else: api_key=st.text_input("Anthropic API Key",type="password")
        _vt=os.environ.get("VT_API_KEY","")
        if _vt: st.success("VirusTotal key configured"); vt_key=_vt
        else: vt_key=st.text_input("VirusTotal API Key (optional)",type="password",help="Get free key at virustotal.com")
        st.divider()
        mitre=get_mitre()
        if mitre.is_loaded(): st.success(f"MITRE loaded - {mitre.count()} techniques")
        else: st.error(f"MITRE load failed: {mitre._error or 'unknown error'}")

    st.markdown("""<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&display=swap" rel="stylesheet">
<h1 style="font-family:'Bebas Neue',sans-serif;font-size:3em;letter-spacing:0.05em;margin-bottom:0;">MITIGATION STATION</h1>""", unsafe_allow_html=True)
    st.caption("Powered by Claude AI + MITRE ATT&CK")
    tab1,tab2,tab3=st.tabs(["Analyze Alert","Technique Lookup","About"])

    with tab1:
        st.markdown("### Paste your security alert below")
        alert_text=st.text_area("Alert",height=250,placeholder="Paste alert text here...",label_visibility="collapsed")
        c1,c2=st.columns([1,4])
        with c1: go=st.button("Analyze",type="primary",use_container_width=True)
        with c2:
            if st.button("Load Example Alert",use_container_width=True):
                st.session_state["ex"]=True; st.rerun()
        if st.session_state.get("ex"):
            st.session_state["ex"]=False; alert_text=EXAMPLE_ALERT
            st.text_area("Alert (example)",value=EXAMPLE_ALERT,height=250,label_visibility="collapsed",key="ex_disp")

        if go and alert_text.strip():
            if not api_key: st.error("Enter API key in sidebar."); st.stop()
            if not mitre.is_loaded(): st.error("MITRE data missing."); st.stop()
            analyzer=ClaudeAnalyzer(api_key=api_key)
            with st.spinner("Analyzing alert..."):
                try: analysis=analyzer.extract_techniques(alert_text)
                except Exception as e: st.error(f"API error: {e}"); st.stop()
            if "error" in analysis: st.error(str(analysis)); st.stop()
            techs=analysis.get("techniques",[])
            techs.sort(key=lambda t: CONF_ORDER.get(t.get("confidence","").lower(),99))
            analysis["techniques"]=techs
            details=[mitre.get_technique(t.get("id","")) or mitre.search_by_name(t.get("name","")) or {} for t in techs]
            mits={}; bar=st.progress(0,text="Generating MITRE checklists...")
            for i,t in enumerate(techs):
                merged={**t,**(details[i] if i<len(details) else {})}
                try: mits[t.get("id","")]=analyzer.generate_mitigations(merged)
                except Exception as e: mits[t.get("id","")]={"error":str(e)}
                bar.progress((i+1)/len(techs),text=f"Processing {t.get('id','')}...")
            bar.empty()
            with st.spinner("Generating threat intelligence..."):
                try: threat_intel=analyzer.generate_threat_intel(analysis)
                except Exception as e: threat_intel={"error":str(e)}
            vt_results={}; iocs=analysis.get("iocs",[])
            if vt_key and iocs:
                vt_bar=st.progress(0,text="Querying VirusTotal...")
                for i,ioc in enumerate(iocs):
                    result=vt_lookup(ioc.get("value",""),ioc.get("type",""),vt_key)
                    if result: vt_results[ioc.get("value","")]=result
                    vt_bar.progress((i+1)/max(len(iocs),1))
                vt_bar.empty()
            st.session_state.update({"analysis":analysis,"alert":alert_text,"mits":mits,"details":details,"threat_intel":threat_intel,"vt_results":vt_results})

        if "analysis" in st.session_state:
            a=st.session_state["analysis"]
            st.divider()
            st.markdown(f"<div style='{SECTION}'>Overview</div>",unsafe_allow_html=True)
            meta=a.get("metadata",{}) or {}
            sev=a.get("severity","unknown"); sc=SEV_COLOR.get(sev.lower(),"#6c757d")
            r1,r2,r3=st.columns(3)
            r1.metric("User",meta.get("user","unknown")); r2.metric("Device",meta.get("host","unknown")); r3.metric("Time of Incident",meta.get("timestamp","unknown"))
            st.markdown("<div style='margin-top:12px;'></div>",unsafe_allow_html=True)
            s1,s2,s3=st.columns(3)
            with s1: st.markdown(f"<div><div style='font-size:0.85em;'>Severity</div><div style='color:{sc};font-size:1.6em;font-weight:bold;'>{sev.upper()}</div></div>",unsafe_allow_html=True)
            s2.metric("Techniques",len(a.get("techniques",[])))
            s3.metric("Threat Name",a.get("threat_name","Unknown"))
            st.markdown("<div style='margin-top:16px;'></div>",unsafe_allow_html=True)
            st.info(a.get("summary",""))

            iocs=a.get("iocs",[])
            if iocs:
                st.markdown(f"<div style='{SECTION}'>Indicators of Compromise</div>",unsafe_allow_html=True)
                vt_results=st.session_state.get("vt_results",{})
                for ioc in iocs:
                    val=ioc.get("value",""); itype=ioc.get("type","").upper(); vt=vt_results.get(val)
                    col1,col2,col3=st.columns([3,1,2])
                    with col1: st.code(val,language=None)
                    with col2: st.caption(itype)
                    with col3:
                        if vt and vt.get("malicious") is not None:
                            sc2="#dc3545" if vt["malicious"]>5 else "#e6a817" if vt["malicious"]>0 else "#28a745"
                            st.markdown(f"<a href='{vt['gui']}' target='_blank' style='color:{sc2};font-weight:bold;'>VT: {vt['malicious']}/{vt['total']} malicious</a>",unsafe_allow_html=True)
                        elif vt and vt.get("gui"): st.markdown(f"[View on VirusTotal]({vt['gui']})")
                        else: st.markdown(f"[Search VirusTotal](https://www.virustotal.com/gui/search/{val})")

            st.markdown(f"<div style='{SECTION}'>MITRE ATT&CK Techniques</div>",unsafe_allow_html=True)
            st.caption("Sorted by confidence: High (red) > Medium (yellow) > Low (green)")
            for i,t in enumerate(a.get("techniques",[])):
                d=st.session_state["details"][i] if i<len(st.session_state["details"]) else {}
                m=st.session_state["mits"].get(t.get("id",""),{})
                render_card(t,d,m)

            ti=st.session_state.get("threat_intel",{})
            if ti and "error" not in ti and ti.get("specific_remediation"):
                st.markdown(f"<div style='{SECTION}'>Threat-Specific Remediation</div>",unsafe_allow_html=True)
                st.caption(f"Steps tailored for: {a.get('threat_name','this threat')}")
                for step in ti.get("specific_remediation",[]): st.checkbox(step,key=f"ts_{step[:30]}")

            if ti and "error" not in ti:
                st.markdown(f"<div style='{SECTION}'>Threat Intelligence</div>",unsafe_allow_html=True)
                tc1,tc2=st.columns(2)
                with tc1:
                    if ti.get("threat_background"): st.markdown("**Background**"); st.write(ti["threat_background"])
                    if ti.get("estimated_victims"): st.metric("Known Scale",ti["estimated_victims"])
                with tc2:
                    if ti.get("targeted_industries"):
                        st.markdown("**Targeted Industries**")
                        for ind in ti.get("targeted_industries",[]): st.markdown(f"- {ind}")
                osint=ti.get("osint_links",[])
                if osint:
                    st.markdown("**Open Source Intelligence**")
                    for link in osint:
                        url=link.get("url",""); title=link.get("title",url); desc=link.get("description","")
                        st.markdown(f"- [{title}]({url})"+(f" - {desc}" if desc else ""))

            st.divider()
            if st.button("Generate PDF Report"):
                try:
                    pdf=PDFGenerator().generate(st.session_state["alert"],a,st.session_state["details"],st.session_state["mits"])
                    st.download_button("Download PDF",pdf,"threat_report.pdf","application/pdf")
                except Exception as e: st.error(f"PDF error: {e}")

    with tab2:
        if not mitre.is_loaded(): st.warning("MITRE data not loaded.")
        else:
            q=st.text_input("Technique ID or name (e.g. T1059.001)")
            if q:
                r=mitre.get_technique(q) or mitre.search_by_name(q)
                if r:
                    st.markdown(f"### {r['id']} - {r['name']}")
                    st.markdown(f"**Tactics:** {', '.join(r.get('tactics',[]))} | **Platforms:** {', '.join(r.get('platforms',[]))}")
                    if r.get("url"): st.markdown(f"[MITRE ATT&CK]({r['url']})")
                    st.write(r.get("description",""))
                else: st.warning("Not found.")

    with tab3:
        st.markdown("## About\nMitigation Station maps security alerts to MITRE ATT&CK and generates AI-powered remediation.\n\n**Stack:** Streamlit + Claude API + MITRE ATT&CK + ReportLab\n\n**Features:** IOC extraction, VirusTotal links, threat-specific remediation, OSINT links")

if __name__=="__main__": main()