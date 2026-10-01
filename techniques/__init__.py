"""
Реестр доступных техник эмуляции атак MITRE ATT&CK
"""

from typing import List, Type
from core.base_technique import BaseTechnique
from techniques.t1082_system_info import T1082SystemInfo
from techniques.t1087_account_discovery import T1087AccountDiscovery
from techniques.t1057_process_discovery import T1057ProcessDiscovery
from techniques.t1547_registry_run import T1547RegistryRun
from techniques.t1053_scheduled_task import T1053ScheduledTask
from techniques.t1027_obfuscation import T1027Obfuscation
from techniques.t1070_indicator_removal import T1070IndicatorRemoval
from techniques.t1548_uac_check import T1548UacBypassCheck
from techniques.t1003_credential_access import T1003CredentialAccessSim
from techniques.t1048_exfiltration_sim import T1048ExfiltrationSim


ALL_TECHNIQUES: List[Type[BaseTechnique]] = [
    T1082SystemInfo,
    T1087AccountDiscovery,
    T1057ProcessDiscovery,
    T1547RegistryRun,
    T1053ScheduledTask,
    T1027Obfuscation,
    T1070IndicatorRemoval,
    T1548UacBypassCheck,
    T1003CredentialAccessSim,
    T1048ExfiltrationSim,
]


def get_all_technique_instances() -> List[BaseTechnique]:
    """Возвращает инициализированные экземпляры всех техник."""
    return [cls() for cls in ALL_TECHNIQUES]
