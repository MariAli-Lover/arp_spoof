# arp_spoof

##사용법과 원리
1. `./arp_spoof <interface> <sender ip> <target ip> [<sender ip> <target ip>]`
2. sender ip와 target ip의 정보를 알아온다.
3. sender에 ARP Spoofing 공격을 실시한다.
4. 이후 Packet Relaying을 실시한다.

##주의할 점
thread의 동시 작동까지는 구현하였으나 상대적으로 속도가 느려져 relay가 제대로 동작하는지 확인에 어려움을 겪고 있습니다. 순수히 relay 기능에 집중한 예제에서는 relay에 성공하였으니 이 점 유의 부탁드립니다.
