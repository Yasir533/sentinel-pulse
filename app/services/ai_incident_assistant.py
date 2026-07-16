from app.models.incident import Incident

class AIIncidentAssistant:
    """
    AI Incident Assistant service to dynamically analyze security incidents
    and provide summary, root cause, resolution steps, business impact, and prevention suggestions.
    """

    @staticmethod
    def generate_assistance(incident: Incident) -> dict:
        """
        Analyze incident context and generate security mitigation details.
        """
        title = incident.title.lower() if incident.title else ""
        desc = incident.description.lower() if incident.description else ""
        severity = incident.severity or "Medium"
        
        # Determine likely attack vector
        attack_vector = "Social Engineering"
        if "apk" in title or "apk" in desc or "malware" in title or "malware" in desc or "trojan" in title or "trojan" in desc:
            attack_vector = "Malware"
        elif "phish" in title or "phish" in desc or "link" in title or "link" in desc or "url" in title or "url" in desc:
            attack_vector = "Phishing"
        elif "sms" in title or "sms" in desc or "scam" in title or "scam" in desc:
            attack_vector = "SMS Scam"
        elif "upi" in title or "upi" in desc or "pin" in title or "pin" in desc:
            attack_vector = "UPI / Financial Fraud"
        elif "ransomware" in title or "ransomware" in desc:
            attack_vector = "Ransomware"
        elif "login" in title or "login" in desc or "auth" in title or "auth" in desc:
            attack_vector = "Credential Access"

        # 1. Summary
        summary = f"This is a {severity}-severity security incident involving a suspected {attack_vector} vector. "
        if incident.incident_number:
            summary += f"Identified as case {incident.incident_number}, the threat is currently under status '{incident.status}'."
        else:
            summary += "The threat is currently being actively triaged by the Security Operations Center."

        # 2. Root Cause
        if attack_vector == "Malware":
            root_cause = "The user downloaded or sideloaded an untrusted APK application package matching a suspicious or malicious signature onto a mobile device."
        elif attack_vector == "Phishing":
            root_cause = "A suspicious web address (URL) was received via SMS, WhatsApp, or Email. The user was lured via social engineering to navigate to the link."
        elif attack_vector == "SMS Scam":
            root_cause = "An unsolicited text message utilizing high-urgency language or bank/courier impersonation tricks was received and flag-checked."
        elif attack_vector == "UPI / Financial Fraud":
            root_cause = "A collect request or deceptive UPI link was triggered, falsely claiming a cash prize or refund to bait the user into typing their secret PIN."
        elif attack_vector == "Ransomware":
            root_cause = "A malicious file execution payload attempted to run file encryption routines, requesting cryptocurrency payments to release keys."
        elif attack_vector == "Credential Access":
            root_cause = "Credential harvesting decoy or suspicious netbanking redirection links triggered system warnings."
        else:
            # Social Engineering
            root_cause = "The victim was manipulated via impersonation, trust relationship exploitation, or pretexting to bypass security controls."

        # 3. Resolution Steps
        if attack_vector == "Malware":
            resolution_steps = [
                "Isolate the affected mobile device from the corporate network and Wi-Fi immediately.",
                "Uninstall the malicious APK package file and check for persistent system services.",
                "Perform a complete anti-malware system scan and reset all compromised user credentials."
            ]
        elif attack_vector == "Phishing":
            resolution_steps = [
                "Block the malicious domain name/URL on the enterprise DNS server and firewalls.",
                "Purge matching phishing emails or block SMS sender IDs from operator routing.",
                "Check web proxy logs to determine if any internal users visited the destination."
            ]
        elif attack_vector == "UPI / Financial Fraud":
            resolution_steps = [
                "Immediately contact the payment gateway or bank to freeze affected accounts.",
                "Report transaction details to the national cybercrime coordination portal.",
                "Reset the UPI PIN and update bank application access passwords."
            ]
        elif attack_vector == "Ransomware":
            resolution_steps = [
                "Isolate the infected hosts from the network immediately to prevent lateral spread.",
                "Locate and verify clean offline backup restore points for data recovery.",
                "Preserve logs, memory snapshots, and encrypted samples for forensic analysis."
            ]
        elif attack_vector == "Credential Access":
            resolution_steps = [
                "Force a global password reset for all affected identity accounts.",
                "Terminate all active sessions on the identity provider and log out user devices.",
                "Enable/enforce multi-factor authentication (MFA) and audit access logs for rogue API keys."
            ]
        elif attack_vector == "SMS Scam":
            resolution_steps = [
                "Report the malicious sender ID and sender numbers to cellular service providers.",
                "Inform users of the ongoing spam/phishing campaign to raise situational awareness.",
                "Block any destination domains contained within the scam message on DNS gateways."
            ]
        else:
            # Social Engineering
            resolution_steps = [
                "Conduct a prompt post-incident verification of the user's reported access levels.",
                "Revoke unauthorized access and monitor corresponding identity logs for anomalies.",
                "Deliver targeted security awareness training to the affected users or department."
            ]

        # 4. Business Impact
        if severity == "Critical":
            business_impact = "High Risk. Direct potential for significant financial loss, critical server lockout, or database credential exposures."
        elif severity == "High":
            business_impact = "Medium-High Risk. Potential exposure of operator devices, localized access disruption, and corporate spam campaigns."
        else:
            business_impact = "Low-Medium Risk. Minor security exposure, contained localized warnings, with low likelihood of broader escalation."

        # 5. Prevention Suggestions
        if attack_vector == "Malware":
            prevention_suggestions = [
                "Enforce strict mobile device management (MDM) rules preventing sideloading of third-party APKs.",
                "Install reliable mobile endpoint protection (EPP/EDR) tools on all corporate devices.",
                "Conduct regular audits of installed applications and device security compliance states."
            ]
        elif attack_vector == "Phishing":
            prevention_suggestions = [
                "Deploy secure email/SMS gateways with automated link-checking heuristics.",
                "Educate employees on how to spot domain spoofing and look-alike URLs.",
                "Implement multi-factor authentication (MFA) to minimize credential harvesting impact."
            ]
        elif attack_vector == "SMS Scam":
            prevention_suggestions = [
                "Set up operator-level SMS spam filtering and sender validation registry rules.",
                "Deliver specific phishing awareness campaigns focusing on text message channels (Smishing).",
                "Establish clear guidelines that corporate accounts will never contact users via SMS for sensitive updates."
            ]
        elif attack_vector == "UPI / Financial Fraud":
            prevention_suggestions = [
                "Enforce mandatory multi-operator verification for corporate funds transfers and transactions.",
                "Provide ongoing customer/staff training on UPI PIN safety and money request concepts.",
                "Configure transaction alerts and speed limits on all operational bank channels."
            ]
        elif attack_vector == "Ransomware":
            prevention_suggestions = [
                "Maintain offline, immutable backups of critical directories and server states regularly.",
                "Restrict user execution privileges and use application whitelisting policies.",
                "Patch software vulnerabilities and keep local system OS definitions up to date."
            ]
        elif attack_vector == "Credential Access":
            prevention_suggestions = [
                "Enforce strong password complexity rules and passwordless authentication strategies.",
                "Monitor logins for impossible travel anomalies and credential stuffing patterns.",
                "Restrict administrative access to systems via localized privileged access workstations."
            ]
        else:
            # Social Engineering
            prevention_suggestions = [
                "Establish strict out-of-band verification protocols for requests involving financial or access changes.",
                "Conduct regular simulated social engineering tests to build strong verification habits.",
                "Encourage an open reporting culture for any suspicious internal or external communications."
            ]

        return {
            "summary": summary,
            "root_cause": root_cause,
            "resolution_steps": resolution_steps,
            "business_impact": business_impact,
            "prevention_suggestions": prevention_suggestions
        }

