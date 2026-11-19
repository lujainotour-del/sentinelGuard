import time
import pandas as pd
import streamlit as st
from google import genai

st.set_page_config(page_title="sentinelGuard - IAM Compliance", layout="wide")

st.title("sentinelGuard: AI-Driven Enterprise IAM Assistant")
st.markdown("Analyze user access logs and detect compliance or privilege anomalies using Gemini AI.")
st.markdown("---")

def generate_local_fallback_report(df: pd.DataFrame) -> str:
    findings = []
    for idx, row in df.iterrows():
        user = str(row.get("Username", "unknown"))
        ip = str(row.get("IP_Address", "unknown"))
        action = str(row.get("Action", "unknown"))
        resource = str(row.get("Resource", "unknown"))
        status = str(row.get("Status", "unknown"))
        is_private_ip = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))
        if "PRIVILEGE_ESCALATION" in action.upper() and status.upper() == "SUCCESS":
            findings.append(f"- **Critical Privilege Escalation:** User `{user}` succeeded at `{action}` on `{resource}` from IP `{ip}` (external/non-RFC1918: `{not is_private_ip}`).")
        elif "EXPORT" in action.upper() and status.upper() == "SUCCESS":
            findings.append(f"- **Sensitive Data Export:** User `{user}` performed `{action}` on `{resource}` from `{ip}`.")
        elif "FAILED" in action.upper() or status.upper() == "FAILURE":
            findings.append(f"- **Failed Access Attempt:** User `{user}` had `{action}` (`{status}`) on `{resource}` from IP `{ip}`.")
    if not findings:
        findings.append("- No high-risk anomalies matched the deterministic rules; review full log table manually.")
    report = [
        "*(Generated via local fallback mode because Gemini returned 503 high-demand errors.)*",
        "",
        "### 1. Executive Summary",
        f"Evaluated **{len(df)}** access log entries and flagged **{len(findings)}** notable IAM/compliance items.",
        "",
        "### 2. Detected Anomalies / Security Risks",
        *findings,
        "",
        "### 3. Recommended Remediation Actions",
        "- Immediately audit successful privilege escalations and verify approval tickets and source IP reputation.",
        "- Review bulk or sensitive data exports (`EXPORT_DATA`) for least-privilege and DLP compliance.",
        "- Monitor repeated `LOGIN_FAILED` events targeting privileged endpoints (such as `/admin_panel`) and enforce MFA/IP controls."
    ]
    return "\n".join(report)

uploaded_file = st.file_uploader("Upload Access Logs (CSV format)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("Uploaded Access Logs Preview")
    st.dataframe(df)

    st.markdown("---")
    st.subheader("Enter Your Gemini API Key")
    api_key_input = st.text_input("Gemini API Key", type="password", placeholder="Paste your API key here...")

    st.markdown("---")
    if st.button("Run AI Compliance Audit"):
        if not api_key_input:
            st.error("Please enter your Gemini API key above before running the audit.")
        else:
            with st.spinner("Analyzing access logs with Gemini AI..."):
                client = genai.Client(api_key=api_key_input.strip())
                log_data_str = df.to_string(index=False)
                prompt = "You are an expert Enterprise IAM and cybersecurity compliance auditor. Analyze these access logs for security anomalies, unauthorized privilege escalations, suspicious IP addresses, or compliance risks and provide 1. Executive Summary, 2. Detected Anomalies / Security Risks, and 3. Recommended Remediation Actions:\n\n" + log_data_str
                response = None
                last_error = None
                for attempt in range(3):
                    try:
                        response = client.models.generate_content(model="gemini-3.8-flash", contents=prompt)
                        break
                    except Exception as e:
                        last_error = e
                        if "503" in str(e) and attempt < 2:
                            time.sleep(2 * (attempt + 1))
                        else:
                            break
                report_text = None
                if response is not None:
                    st.success("Audit Complete (Gemini AI)!")
                    report_text = response.text
                elif last_error is not None and "503" in str(last_error):
                    st.warning("Gemini is temporarily experiencing high demand (503). Generated a local rule-based audit report so you can continue working.")
                    report_text = generate_local_fallback_report(df)
                else:
                    st.error(f"Audit failed: {last_error}")
                if report_text is not None:
                    st.markdown("### IAM Compliance Audit Report")
                    st.markdown(report_text)
                    st.download_button(
                        label="Download Report (.txt)",
                        data=report_text,
                        file_name="sentinelguard_audit_report.txt",
                        mime="text/plain"
                    )
else:
    st.info("Please upload a CSV file above to reveal the API key input and start your audit.")
