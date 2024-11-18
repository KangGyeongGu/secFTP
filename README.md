![보안 도표](https://github.com/user-attachments/assets/cf2a4ed0-74ee-47a6-a4a2-55d59ff006a8)

# 파일 전송 시스템

이 프로젝트는 두 개의 LXC 컨테이너(서버와 클라이언트) 간에 파일을 전송하는 시스템을 구현합니다. 각 컨테이너에서 실행되는 서버와 클라이언트는 OpenSSL 및 pthread 라이브러리를 사용하여 암호화된 파일 전송을 지원합니다.

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
