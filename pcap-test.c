#include <pcap.h> // pcap 라이브러리 헤더
#include <stdbool.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
    printf("[Linux] pcap-test eth0\n");
}

typedef struct {
    char* dev_;// 네트워크 인터페이스 이름
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];// 첫 번째 인수를 네트워크 인터페이스 이름으로 설정?!
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))  // 명령행 인수 파싱 실패 시
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE]; // pcap_open_live() 함수가 실패할 경우 오류 메시지를 저장할 버퍼
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // 네트워크 인터페이스로부터 패킷을 캡처하기 위한 세션 생성
    if (pcap == NULL) { // pcap_open_live() 함수가 실패한 경우
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) { // 패킷 캡처 루프
        struct pcap_pkthdr* header;// 패킷 헤더 구조체 포인터
        const u_char* packet;// 패킷 데이터 버퍼 포인터
        int res = pcap_next_ex(pcap, &header, &packet);// 다음 패킷 캡처
        if (res == 0) continue;// 패킷이 존재하지 않는 경우 다음 패킷으로 건너뛰기
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {// 패킷이 존재하지 않는 경우 다음 패킷으로 건너뛰기
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));







            break;// 루프 종료
        }
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcap);
}
