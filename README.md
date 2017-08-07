# arp_spoof
## A Simple Gadget
###사용법과 원리
1. `./arp_spoof <interface> <sender ip> <target ip> [<sender ip> <target ip>]`
2. sender ip와 target ip의 정보를 알아온다.
3. sender에 ARP Spoofing 공격을 실시한다.
4. 이후 Packet Relaying을 실시한다.
###주의할 점
현재 C++의 thread의 사용이 익숙치 않아 동시에 작동하여야 하는 함수들이 그러지 않고 있습니다. 일단 1개의 session에 대해서는 정상적으로 작동하며 추후 수정 예정입니다.
