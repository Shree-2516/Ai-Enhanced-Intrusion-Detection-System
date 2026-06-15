from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from .database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    attack_type = Column(String(100))
    severity = Column(String(50))

    source_ip = Column(String(50))
    destination_ip = Column(String(50))

    confidence_score = Column(Float)

    detection_time = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


class TrafficRecord(Base):
    __tablename__ = "traffic_records"

    id = Column(Integer, primary_key=True, index=True)
    
    source_ip = Column(String(50))
    destination_ip = Column(String(50))
    destination_port = Column(Integer)
    protocol = Column(String(20))
    packet_length = Column(Integer)
    
    predicted_class = Column(String(100))
    is_anomaly = Column(Integer)  # 0 for safe, 1 for attack
    confidence_score = Column(Float)
    
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )