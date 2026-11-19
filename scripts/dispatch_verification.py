"""Demonstration script: Dispatches real operational emails to the 5 team members."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.services.email_service import EmailNotificationService

init_db()
repo = DataGuardRepository()
svc = EmailNotificationService(repo=repo)
cfg = svc.get_config()

print("Sandbox Mode Status:", "OFF (Real SMTP Active)" if not cfg["mock_mode"] else "ON")
print("Target Recipients:", cfg["recipients"])

print("\n--- Dispatching Real P1 Incident Alert via Gmail SMTP (port 587 STARTTLS) ---")
alert_res = svc.send_sample_incident_alert()

print("Incident Alert Result:")
print("  Overall Status:", alert_res.get("status"))
print("  Delivery Mode:", alert_res.get("mode"))
print("  Emails Attempted:", alert_res.get("attempted"))
print("  Emails Successfully Sent:", alert_res.get("sent_count"))
print("  Emails Failed:", alert_res.get("failed_count"))

print("\nIndividual Per-Recipient Deliveries:")
for r_item in alert_res.get("recipient_results", []):
    recip = r_item.get("recipient")
    st = r_item.get("status")
    print(f"  • {recip} ➜ {st}")

metrics = repo.get_notification_metrics()
print("\n=== UPDATED OBSERVABILITY METRICS ===")
for k, v in metrics.items():
    print(f"  {k}: {v}")
