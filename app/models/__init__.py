# Models package initialization

# Import Base first
from app.core.database import Base

# Import models without relationships first
from .base import (
    User,
    Company,
    Feature,
    CompanyFeature,
    Organization,
    LogType
)

# Import models with relationships
from .base import (
    Network,
    Device,
    UserOrganizationAccess,
    UserNetworkAccess,
    UserFeatureAccess,
    DeviceLog
)

from .compliance import (
    ComplianceScan,
    ComplianceFinding,
    ComplianceFile
)

# Import learning models
from .learning import (
    LearnedPatterns,
    DiscoveryStrategies,
    DeviceCapabilities,
    DiscoveryHistory,
    AdaptiveLearningConfig
)

# Import topology models
from .topology import (
    DeviceTopology,
    InterfaceTopology,
    NeighborTopology
)

# This ensures proper model initialization order
__all__ = [
    'Base',
    'User',
    'Company',
    'Feature',
    'CompanyFeature',
    'Organization',
    'Network',
    'Device',
    'UserOrganizationAccess',
    'UserNetworkAccess',
    'UserFeatureAccess',
    'DeviceLog',
    'LogType',
    'ComplianceScan',
    'ComplianceFinding',
    'ComplianceFile',
    'LearnedPatterns',
    'DiscoveryStrategies',
    'DeviceCapabilities',
    'DiscoveryHistory',
    'AdaptiveLearningConfig',
    'DeviceTopology',
    'InterfaceTopology',
    'NeighborTopology'
]
