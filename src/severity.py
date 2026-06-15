def get_severity(attack_type: str) -> str:
    """
    Categorizes the security severity of network traffic classes.
    DDoS -> CRITICAL
    Botnet -> HIGH
    PortScan -> MEDIUM
    Benign -> LOW
    """
    if not attack_type:
        return "LOW"
        
    val = str(attack_type).strip().lower()
    
    if "ddos" in val or "dos" in val:
        return "CRITICAL"
    elif "bot" in val:
        return "HIGH"
    elif "port" in val:
        return "MEDIUM"
    elif "benign" in val:
        return "LOW"
    elif "brute" in val:
        return "HIGH"
    elif "web" in val:
        return "HIGH"
    else:
        return "HIGH"  # Fallback for unknown threats
