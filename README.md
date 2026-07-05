## 1. 과제 개요

과제는 C 기반 PCAP API를 활용하여 네트워크 패킷을 캡처하고, 패킷 내부의 주요 Header 정보를 출력하는 프로그램을 작성하는 것입니다.

출력 대상은 다음과 같습니다.

```
Ethernet Header : src mac / dst mac
IP Header       : src ip / dst ip
TCP Header      : src port / dst port
HTTP Message    : Application 계층 데이터
```

구현은 강의자료의 `sniff_improved.c`와 `myheader.h` 코드를 참고하여 작성하였습니다.

---

## 2. 패킷 구조 이해

Ethernet 기반 IPv4 TCP 패킷은 다음과 같은 구조로 구성됩니다.

```
[ Ethernet Header ][ IP Header ][ TCP Header ][ Application Data ]
```

Ethernet Header에는 출발지 MAC 주소와 목적지 MAC 주소가 포함됩니다.

IP Header에는 출발지 IP 주소와 목적지 IP 주소가 포함됩니다. 또한 Protocol 필드를 통해 상위 계층 프로토콜이 TCP인지 UDP인지 확인할 수 있습니다.

TCP Header에는 출발지 포트와 목적지 포트가 포함됩니다.

HTTP Message는 TCP 위에서 동작하는 Application 계층 데이터이므로, TCP Header 뒤의 Payload 영역에 존재합니다.

따라서 본 프로그램은 패킷을 Ethernet Header, IP Header, TCP Header, HTTP Message 순서로 분석하도록 구현하였습니다.

---

## 3. 구현 방법

프로그램은 `pcap_open_live()` 함수를 사용하여 네트워크 인터페이스에서 패킷을 캡처합니다. 이후 `pcap_compile()`과 `pcap_setfilter()`를 사용하여 `"tcp"` 필터를 적용하였습니다.

이 필터를 통해 TCP 패킷만 캡처되도록 하였고, UDP 패킷은 처리 대상에서 제외하였습니다.

패킷이 캡처되면 `pcap_loop()`에 등록된 callback 함수인 `got_packet()`이 실행됩니다. 이 함수에서 캡처된 `packet` 포인터를 기준으로 각 Header를 순서대로 파싱하였습니다.

전체 처리 흐름은 다음과 같습니다.

```
1. Ethernet Header 파싱
2. IPv4 패킷인지 확인
3. IP Header 파싱
4. TCP 패킷인지 확인
5. IP Header 길이 계산
6. TCP Header 파싱
7. TCP Header 길이 계산
8. TCP Payload 위치 계산
9. HTTP Message 출력
```

---

## 4. Header 정보 출력

Ethernet Header에서는 다음 정보를 출력하였습니다.

```
src mac
dst mac
```

IP Header에서는 다음 정보를 출력하였습니다.

```
src ip
dst ip
```

TCP Header에서는 다음 정보를 출력하였습니다.

```
src port
dst port
```

패킷 내부의 `EtherType`, `IP total length`, `TCP port`와 같은 2바이트 이상의 값은 Network Byte Order로 저장되어 있습니다. 따라서 값을 올바르게 출력하기 위해 `ntohs()` 함수를 사용하여 Host Byte Order로 변환하였습니다.

---

## 5. Header 길이 계산

본 과제에서 가장 중요한 부분은 IP Header와 TCP Header의 길이를 고정값으로 가정하지 않는 것입니다.

IPv4 Header는 기본적으로 20바이트이지만, Options 필드가 존재하면 더 길어질 수 있습니다. 따라서 IP Header의 실제 길이는 Header Length 필드를 이용하여 계산하였습니다.

```c
ip_header_len = IP_HL(ip) * 4;
```

TCP Header도 기본적으로 20바이트이지만, TCP Options가 존재하면 길이가 달라질 수 있습니다. 따라서 TCP Header의 실제 길이는 Data Offset 필드를 이용하여 계산하였습니다.

```c
tcp_header_len = TH_OFF(tcp) * 4;
```

HTTP Message의 시작 위치는 다음과 같이 계산하였습니다.

```c
payload = packet + SIZE_ETHERNET + ip_header_len + tcp_header_len;
```

이렇게 계산하면 IP Options 또는 TCP Options가 포함된 패킷에서도 TCP Payload의 시작 위치를 정확하게 찾을 수 있습니다.

---

## 6. HTTP Message 출력

HTTP Message는 TCP Header 뒤의 Payload 영역에 존재합니다. 따라서 IP 전체 길이에서 IP Header 길이와 TCP Header 길이를 제외하여 Payload 길이를 계산하였습니다.

```c
payload_len = ip_total_len - ip_header_len - tcp_header_len;
```

Payload가 존재하고, 내용이 HTTP 형식으로 보이면 이를 HTTP Message로 출력하였습니다. 일반적인 HTTP 요청은 `GET`, `POST`, `HEAD` 등으로 시작하고, HTTP 응답은 `HTTP/1.1`과 같은 문자열로 시작합니다.

단, HTTPS는 암호화되어 있기 때문에 HTTP Message가 평문으로 보이지 않습니다. 따라서 HTTPS 패킷의 경우 TCP Payload가 존재하더라도 사람이 읽을 수 있는 HTTP Message 형태로 출력되지 않을 수 있습니다.

---

## 7. 실행 방법

컴파일은 다음 명령어로 진행하였습니다.

```bash
gcc -Wall -Wextra -std=c11 sniff_improved.c -o pcap_sniffer -lpcap
```

네트워크 인터페이스 이름은 다음 명령어로 확인하였습니다.

```bash
ip -br address
```

예를 들어 인터페이스 이름이 `enp0s3`인 경우 다음과 같이 실행하였습니다.

```bash
sudo ./pcap_sniffer enp0s3
```

PCAP을 사용하여 실제 네트워크 인터페이스의 패킷을 캡처하기 때문에 관리자 권한이 필요합니다.

---

## 8. 실행 결과

프로그램 실행 결과 TCP 패킷이 캡처될 때마다 다음과 같은 정보가 출력되었습니다.

```
========== Packet #1 ==========
Ethernet Header
  src mac : ...
  dst mac : ...

IP Header
  src ip  : ...
  dst ip  : ...
  ip_header_len : 20 bytes

TCP Header
  src port : ...
  dst port : ...
  tcp_header_len : 20 bytes

HTTP Message
GET / HTTP/1.1
Host: ...
```

이를 통해 Ethernet Header의 출발지/목적지 MAC 주소, IP Header의 출발지/목적지 IP 주소, TCP Header의 출발지/목적지 포트 번호가 정상적으로 출력되는 것을 확인하였습니다.

또한 HTTP 평문 트래픽의 경우 TCP Payload 영역에 포함된 HTTP Message가 출력되는 것을 확인하였습니다.

---

## 9. 결론

과제를 통해 PCAP API를 사용하여 네트워크 패킷을 직접 캡처하고, 패킷을 계층별로 분석하는 방법을 이해하였습니다.

패킷은 Ethernet Header, IP Header, TCP Header, Application Data 순서로 구성되어 있으며, 각 Header의 위치를 정확히 계산해야 원하는 정보를 올바르게 출력할 수 있습니다.
