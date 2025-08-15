from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from app.db.base_class import Base

class Interface(Base):
    __tablename__ = "interfaces"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(String)
    interface_type = Column(String)
    admin_status = Column(String)
    oper_status = Column(String)
    mac_address = Column(String)
    ip_address = Column(String)
    subnet_mask = Column(String)
    speed = Column(String)
    duplex = Column(String)
    last_polled = Column(DateTime)
    config_data = Column(JSON)

    # Relationships
    device = relationship("Device", back_populates="interfaces")
    interface_topology = relationship("InterfaceTopology", back_populates="interface", uselist=False, cascade="all, delete-orphan") 