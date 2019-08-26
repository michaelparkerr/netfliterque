#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int flag=0;
char juso[255];
void dump(unsigned char* buf, int size) {//void 반환형의 dump. unsigned char 포인터형 변수 buf, int자료형의 size를 인자로 받음.
	int i;//변수 i 선언
	for (i = 0; i < size; i++) { //size 만큼 반복하는 반복문
		if (i % 16 == 0)  //i가 16번 출력될 때마다 줄바꿈해주는 조건
			printf("\n");
		printf("%02x ", buf[i]);//for문 돌아가면서 buf 안의 배열을 hex로 2글자씩 출력
	}
}
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) //한번 선언되면 초기화되지 않는 static 변수인 부호 없는 4바이트 print_pkt.인자는 구조체 nfq_data 의 pointer형 변수를 받음
{
	int id = 0;//id 변수 선언
	struct nfqnl_msg_packet_hdr *ph;//nfqnl_msg_packet_hdr 구조체의 ph라는 포인터형 변수를 선언.
	struct nfqnl_msg_packet_hw *hwph;//nfql_msg_packet_hw 구조체의 hwph라는 포인터형 변수를 선언.
	u_int32_t mark,ifi; //mark, ifi 부호없는 4바이트 변수 선언
	int ret;//ret변수 선언
	unsigned char *data;//부호없는 char 포인터형 변수data 선언

	ph = nfq_get_msg_packet_hdr(tb);//ph안에 nfq_get_msg_packet_hdr(tb)의 결과를 넣음.
	if (ph) {//결과가 있으면
		id = ntohl(ph->packet_id);//ph의 packet_id를 리틀엔디언으로 바꿔서 id에 넣는다.
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);//ph의 hw_protocol을 리틀엔디언으로 바꿔서 ph->hook를 출력, id를 출력한다.
	}

	hwph = nfq_get_packet_hw(tb);//인자의 주소값을 hwph에 넣는다.
	if (hwph) {//hwph가 존재하면 
		int i, hlen = ntohs(hwph->hw_addrlen);//i선언 hlen 에 hwph의 hw_addrlen를 리틀엔디언으로 바꿔서 hlen에 삽입

		printf("hw_src_addr=");//출력 준비
		for (i = 0; i < hlen-1; i++)//for문 돌리면서 배열의 하나씩 출력
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);//[hlen-1]위치에 있는 것은 따로 출력
	}

	mark = nfq_get_nfmark(tb);//mark에 nfq_get_nfmark에 tb인자 넣은 값을 삽입.
	if (mark)//존재하면 출력
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);//ifi에 indev,outdev,phsindev,physoutdev차례대로 넣고 출력
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
//ret에 nfq_get_payload의 tb와 &data값을 넣은 결과 값을 넣고
	ret = nfq_get_payload(tb, &data);
	dump(data, ret);//ret길이만큼 data를 dump
	if (data[9]==6)
	{
		//printf("\n======\n");
		//printf("TCP\n");
		//printf("======\n");
		int k=(data[0]&0x0F)*4;
		int k1=(data[12+k]>>4)*4;
	//	int b = memcmp(data[k+k1+26],juso,strlen(juso));	
		if((((data[k]<<8)|data[1+k])==80 || ((data[2+k]<<8)|data[3+k])== 80)&&(0x474554==(data[k+k1]<<16|data[1+k+k1]<<8|data[2+k+k1])))
		{
			
		printf("\n======\n");
		printf("TCP+port80+GET\n");
		printf("\n======\n");
		flag = 1;
	//	printf("memcmp results : %d\n",b);
		}
	}
	else
	{
		flag = 0;
	}
		
	if (ret >= 0)//ret이 0보다 같거나 크면
		printf("payload_len=%d ", ret);//길이 알려줌

	fputc('\n', stdout);//파일에 \n캐릭터 값을 씀.

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);//u_int_32_t id에 print_pkt(nfa)값을 넣는다
	printf("entering callback\n");
	if (flag==1)
	{
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);//id를 DROP시킨다.
	}
	else
	{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);//id를 DROP시킨다.
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;//nfq_handle의 pointer형 변수 h선언
	struct nfq_q_handle *qh;//nfq_q_handle의 pointer형 변수 qh선언
	struct nfnl_handle *nh;//nfnl_handle 의 pointer형 변수 nh선언
	int fd;//int fd 선언
	int rv;//int rv 선언
	char buf[4096] __attribute__ ((aligned));//char buf[4096] 배열선언 aligned 된 __attribute__
	scanf("%s",juso);
	printf("opening library handle\n");
	h = nfq_open();//h에 nfq_open()넣음
	if (!h) {//h가 거짓. 즉 open안됬으면 에러출력
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
//아니면 언바인딩된 nf_que handler있다고 출력
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}//nfq_unbind_pf의 결과가 0보다 작으면 에러 출력
//잡고 있다고 출력
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}//nfq_bind_pf가 0보다 작으면 에러 출력
//이 소켓에 que잡고 있다고 출력
	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);//qh에 nfq_create_queue 넣기
	if (!qh) {//qh가 없으면 
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);//nfq하다가 에러났다고 출력
	}
//seeting copy_packet mode출력
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}//nfq_set_mode가 0보다 작으면 에러 출력
//fd에 nfq_fd(h)넣기
	fd = nfq_fd(h);
//for문 이하 내용 무한 반복
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {//rv에 recv값을 넣고 그게 0보다 크거나 같으면 pkt받았다고 출력
//nfq_handle_packet으로 h,buf,rv인자로 받고 또 반복
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {//rv가 0보다 작거나 errno가 ENOBUFS면 패킷 잃어버렸다고 출력
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");//그외의 경우 받기 실패이므로 break
		break;
	}

	printf("unbinding from queue 0\n");//unbinding이후 nfq_destroy_queue(qh)해줌
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);//nfq_unbind_pf로 h와 AF_INET인자 받고 출력
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

