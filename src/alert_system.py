from db.models import Alert
from src.severity import get_severity

def assign_severity(attack_type: str) -> str:
    """
    Determines and returns the severity level of a given attack type.
    """
    return get_severity(attack_type)

def generate_notifications(alert: Alert):
    """
    Prints a notification to the console when an alert is generated,
    highlighting critical/high severities.
    """
    if alert.severity in ["CRITICAL", "HIGH"]:
        print(
            f"\n[!!! SECURITY NOTIFICATION - {alert.severity} !!!]\n"
            f"An intrusion hazard has been identified!\n"
            f"Attack Type: {alert.attack_type}\n"
            f"Source IP: {alert.source_ip} -> Destination IP: {alert.destination_ip}\n"
            f"Confidence: {alert.confidence_score * 100:.1f}%\n"
            f"Detection Time: {alert.detection_time or 'Just Now'}\n"
        )
    else:
        print(
            f"[Notification - {alert.severity}] Mild security event. "
            f"Type: {alert.attack_type} from {alert.source_ip} to {alert.destination_ip} "
            f"({alert.confidence_score * 100:.1f}% confidence)"
        )

def save_alert(db_session, alert: Alert):
    """
    Saves an alert record into the database session.
    """
    db_session.add(alert)

def create_alert(
    db_session, 
    attack_type: str, 
    source_ip: str, 
    destination_ip: str, 
    confidence_score: float, 
    detection_time=None
) -> Alert:
    """
    Central function to create an alert, assign its severity, save it, 
    and generate notifications.
    """
    severity = assign_severity(attack_type)
    
    alert = Alert(
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        confidence_score=confidence_score,
        detection_time=detection_time
    )
    
    save_alert(db_session, alert)
    generate_notifications(alert)
    return alert
