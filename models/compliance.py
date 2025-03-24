# models/compliance.py

class ComplianceRequirements:
    """Base class for compliance requirements."""
    def __init__(self):
        self.requirements = {}

class GDPRRequirements(ComplianceRequirements):
    """GDPR specific requirements."""
    def __init__(self):
        super().__init__()
        self.requirements = {
            "lawful_basis": "Ensure all data processing activities have a clear lawful basis (e.g., consent, contract, legitimate interest).",
            "data_encryption": "Ensure all data is encrypted at rest and in transit, using strong encryption standards.",
            "access_control": "Restrict access to sensitive data based on the principle of least privilege, ensure multi-factor authentication (MFA) for critical actions.",
            "breach_notifications": "Detect and report data breaches within 72 hours, ensure incident response plans are in place for quick response.",
            "data_minimization": "Ensure only the necessary data is collected and stored, adhering to the data minimization principle.",
            "consent_management": "Ensure proper consent is obtained for collecting personal data and that users can easily withdraw consent.",
            "data_retention": "Ensure data retention policies are in place, and data is deleted after it is no longer necessary for its original purpose.",
            "audit_trail": "Maintain an audit trail of all data processing activities for accountability, especially when personal data is accessed or modified.",
            "data_subject_rights": "Ensure that data subjects' rights (e.g., right to access, right to rectification, right to erasure) are respected.",
            "transparency": "Provide clear and transparent information to data subjects about how their personal data is being processed.",
            "data_protection_by_design_and_default": "Ensure that data protection is integrated into the design of systems and processes, and that only necessary data is processed by default.",
            "international_data_transfers": "Ensure that any personal data transferred outside the EEA complies with GDPR requirements.",
            "dpias": "Conduct Data Protection Impact Assessments (DPIAs) for high-risk data processing activities.",
            "accountability": "Designate a Data Protection Officer (DPO) if necessary, and ensure regular compliance reviews and assessments."
        }

class NIS2Requirements(ComplianceRequirements):
    """NIS2 specific requirements."""
    def __init__(self):
        super().__init__()
        self.requirements = {
            "incident_reporting": "Track and report incidents to regulatory bodies within predefined timeframes.",
            "vulnerability_management": "Implement an ongoing vulnerability management program to identify, assess, and patch vulnerabilities within defined timeframes.",
            "critical_infra_protection": "Protect critical cloud resources from unauthorized access, ensuring strict access controls and protection against DDoS attacks.",
            "network_security": "Implement robust network security measures, including firewalls, intrusion detection systems (IDS), and intrusion prevention systems (IPS).",
            "business_continuity_planning": "Establish business continuity and disaster recovery plans, ensuring regular testing and compliance with recovery time objectives.",
            "access_management": "Implement strong access management, including role-based access control (RBAC) and privileged access management (PAM).",
            "supplier_management": "Ensure that third-party suppliers comply with NIS2 requirements and manage the risks associated with external dependencies.",
            "monitoring_and_detection": "Implement continuous monitoring and detection of cybersecurity threats."
        }
