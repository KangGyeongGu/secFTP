![보안 도표](https://github.com/user-attachments/assets/cf2a4ed0-74ee-47a6-a4a2-55d59ff006a8)

# client-server secFTP 구현 예제
이 프로젝트는 두 개의 LXC 컨테이너(서버와 클라이언트) 간에 파일을 전송하는 시스템을 구현한다.
각 컨테이너에서 실행되는 서버와 클라이언트는 OpenSSL 라이브러리에서 제공하는 암호화 알고리즘을 사용한다.

## 환경설정

### OpenSSL 라이브러리 설치
```
$ sudo apt-get update
$ sudo apt install openssl libssl-dev
```

### Pthread 라이브러리 설치
```
$ sudo apt install libpthread-stubs0-dev
```

### gcc 설치
```
$ gcc --version
$ sudo apt-get install gcc
```

### LXC 설치
```
$ sudo apt update
$ sudo apt install lxc lxc-templates
```

### 초기 설정
```
# 서버 컨테이너 생성
$ sudo lxc-create -n myserver -t ubuntu

# 서버 컨테이너 설정
$ sudo nano /var/lib/lxc/myserver/config
```

### Network configuration
```
# 클라이언트 컨테이너 생성
$ sudo lxc-create -n myclient -t ubuntu

# 클라이언트 컨테이너 설정
$ sudo nano /var/lib/lxc/myclient/config
```

## 기능 설계
client's SEND command
```
# client's example_cdir/send_example.txt -> server's example_sdir/send_example1.txt
$ send example_cdir/send_example.txt example_sdir/send_example1.txt
```

client's RECV command
```
# server's example_sdir/recv_example.txt -> client's example_cdir/recv_example1.txt
$ recv example_cdir/recv_example1.txt example_sdir/recv_example.txt
```

## 서버 로직

### 1. password.txt 파일 형식
- `password.txt` 파일 : 각 줄에 사용자 정보 `[username] : [Salt] : [Salted password Hash]` 형태 저장
- `SHA-512 with Salt` 해시 알고리즘을 사용하여 비밀번호를 해시

### 2. 클라이언트 TCP 연결 요청 처리
- 서버는 클라이언트의 연결 요청을 수신
- TCP 소켓 통신을 통해 연결을 시도하고, 연결 성공 시 응답을 클라이언트에 송신

### 3. RSA 공개키 생성 및 사용자 인증 처리
- TCP 소켓 통신이 성공하면, 서버는 RSA 공개키를 생성하여 클라이언트에 송신
- 클라이언트로부터 수신한 `username`과 `password`는 RSA 개인키로 복호화
- `password.txt` 내에서 해당 `username`이 존재하는지 검증
  - 존재하는 `username`인 경우 비밀번호 해시를 진행하고, 해시 값이 일치하는지 확인
  - 비밀번호 해시가 일치하면 로그인 성공 응답을 클라이언트로 송신
  - `username`이 존재하지 않으면, 회원 가입을 요청하는 응답을 송신

### 4. 클라이언트 대칭키 수신
- 로그인 성공 후, 클라이언트는 RSA 공개키로 대칭키를 암호화하여 서버로 송신
- 서버는 이를 RSA 개인키로 복호화하여 저장하고, 성공 응답을 클라이언트에 송신

## 클라이언트 로직

### 1. TCP 연결 요청
- 사용자는 CLI에서 서버의 IP주소 및 포트 번호를 입력
- 입력받은 주소에 대해 TCP 통신 연결 요청을 서버로 송신
- 연결 요청 성공/실패에 대한 응답을 수신하고, 재시도하거나 다음 단계를 진행

### 2. 사용자 인증 과정
- CLI에서 `username`과 `password`를 차례대로 입력
- 서버로부터 수신한 RSA 공개키를 사용하여 `username`과 `password`를 암호화하여 서버로 송신
- 인증 성공 응답 수신 :
  - 다음 단계를 진행
- 인증 실패 응답 수신 : 
  - 사용자 재입력 유도 및 재송신

### 3. 대칭키 생성 및 송신
- 클라이언트는 AES 대칭키를 생성
- 생성된 AES 대칭키를 RSA 공개키로 암호화하여 서버로 송신
- 서버로부터 성공 응답을 수신하면, 다음 단계를 진행
