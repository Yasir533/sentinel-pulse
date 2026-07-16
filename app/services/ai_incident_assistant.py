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
        else:
            root_cause = "Credential harvesting decoy or suspicious netbanking redirection links triggered system warnings."

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
        else:
            resolution_steps = [
                "Acknowledge the alert, check the source feed, and block matching indicators of compromise.",
                "Conduct a forensic audit of the target client logs to verify if credential sharing occurred.",
                "Quarantine affected hosts or user sessions on the identity server."
            ]

        # 4. Business Impact
        if severity == "Critical":
            business_impact = "High Risk. Direct potential for significant financial loss, critical server lockout, or database credential exposures."
        elif severity == "High":
            business_impact = "Medium-High Risk. Potential exposure of operator devices, localized access disruption, and corporate spam campaigns."
        else:
            business_impact = "Low-Medium Risk. Minor security exposure, contained localized warnings, with low likelihood of broader escalation."

        # 5. Prevention Suggestions
        prevention_suggestions = [
            "Conduct regular employee security awareness training on mobile social engineering schemes.",
            "Enforce strict mobile device management (MDM) rules preventing sideloading of third-party APKs.",
            "Deploy secure email/SMS gateways with automated link-checking heuristics.",
            "Enforce multi-factor authentication (MFA) on all corporate portals to prevent credential abuse."
        ]

        return {
            "summary": summary,
            "root_cause": root_cause,
            "resolution_steps": resolution_steps,
            "business_impact": business_impact,
            "prevention_suggestions": prevention_suggestions
        }
