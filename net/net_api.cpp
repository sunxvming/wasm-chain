#include <sstream>
#include "net_api.h"
#include "./global.h"
#include <string>
#include <arpa/inet.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <errno.h>
#include "./dispatcher.h"
#include "net.pb.h"
#include "common.pb.h"
#include "../utils/singleton.h"
#include "./socket_buf.h"
#include "./work_thread.h"
#include "./epoll_mode.h"
#include "http_server.h"
#include <utility>
#include "node_cache.h"
#include "./ip_port.h"
#include "../common/global.h"
#include "logging.h"

int net_tcp::Socket(int family, int type, int protocol)
{
	int n;

	if ((n = socket(family, type, protocol)) < 0)
		ERRORLOG("can't create socket file");
	return n;
}

int net_tcp::Accept(int fd, struct sockaddr *sa, socklen_t *salenptr)
{
	int n;

	if ((n = accept(fd, sa, salenptr)) < 0)
	{
		if ((errno == ECONNABORTED) || (errno == EINTR) || (errno == EWOULDBLOCK))
		{
			goto ret;
		}
		else
		{
			ERRORLOG("accept error");
		}
	}
ret:
	return n;
}

int net_tcp::Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	int n;

	if ((n = bind(fd, sa, salen)) < 0)
		ERRORLOG("bind error");
	return n;
}

int net_tcp::Connect(int fd, const struct sockaddr *sa, socklen_t salen)
{
	int n;
	/////////////////////////////////////////////////////////////////////
	int nBufLen;
	int nOptLen = sizeof(nBufLen);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&nBufLen, (socklen_t *)&nOptLen);
	//Getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void*)& nBufLen, nOptLen);
	// INFOLOG("socket recv buff default size {} !", nBufLen);

	int nRecvBuf = 1 * 1024 * 1024;
	Setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void *)&nRecvBuf, sizeof(int));
	int nSndBuf = 1 * 1024 * 1024;
	Setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *)&nSndBuf, sizeof(int));

	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&nBufLen, (socklen_t *)&nOptLen);
	//Getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void*)& nBufLen, nOptLen);
	// INFOLOG("modify socket recv buff size {} }!", nBufLen);
	/////////////////////////////////////////////////////////////////////

	// //关闭所有信号
	// int value = 1;
	// setsockopt(fd,SOL_SOCKET,MSG_NOSIGNAL,&value,sizeof(value));

	// sockaddr_in *si = (sockaddr_in *)sa;
	// char addr[20] = {0};
	if ((n = connect(fd, sa, salen)) < 0)
	{
		// DEBUGLOG(RED "Connect fun  {}" RESET, n);
		// printf("to %s/%d connect error : %s\n", inet_ntop(AF_INET, &si->sin_addr.s_addr, addr, sizeof(addr)), ntohs(si->sin_port), strerror(errno));
	}

	return n;
}

int net_tcp::Listen(int fd, int backlog)
{
	int n;

	if ((n = listen(fd, backlog)) < 0)
		ERRORLOG("listen error");
	return n;
}

int net_tcp::Send(int sockfd, const void *buf, size_t len, int flags)
{
	if (sockfd < 0)
	{
		ERRORLOG("Send func: file description err"); // 发送文件描述符错误
		return -1;
	}
	int bytes_left;
	int written_bytes;
	char *ptr;
	ptr = (char *)buf;
	bytes_left = len;
	while (bytes_left > 0)
	{
		written_bytes = write(sockfd, ptr, bytes_left);
		if (written_bytes <= 0) /* 出错了*/
		{
			if (written_bytes == 0)
			{
				continue;
			}
			if (errno == EINTR)
			{
				continue;
			}
			else if (errno == EAGAIN) /* EAGAIN : Resource temporarily unavailable*/
			{

				return len - bytes_left;
			}
			else 
			{
				ERRORLOG("net_tcp::Send write error delete node,fd is:{}",sockfd);
				Singleton<PeerNode>::get_instance()->delete_by_fd(sockfd);
				return -1;
			}
		}

		bytes_left -= written_bytes;
		ptr += written_bytes; /* 从剩下的地方继续写?? */
	}
	return len;
}

int net_tcp::Setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int ret;

	if ((ret = setsockopt(fd, level, optname, optval, optlen)) == -1)
		ERRORLOG("setsockopt error");
	return ret;
}

int net_tcp::listen_server_init(int port, int listen_num)
{
	struct sockaddr_in servaddr;
	int listener;
	int opt = 1;
	listener = Socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // any addr
	servaddr.sin_port = htons(port);

	Setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
			   sizeof(opt));
	Setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, (const void *)&opt,
			   sizeof(opt));

	Bind(listener, (struct sockaddr *)&servaddr, sizeof(servaddr));

	int nRecvBuf = 1 * 1024 * 1024;
	Setsockopt(listener, SOL_SOCKET, SO_RCVBUF, (const void *)&nRecvBuf, sizeof(int));
	int nSndBuf = 1 * 1024 * 1024;
	Setsockopt(listener, SOL_SOCKET, SO_SNDBUF, (const void *)&nSndBuf, sizeof(int));
	Listen(listener, listen_num);

	return listener;
}

int net_tcp::set_fd_noblocking(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK) == -1)
	{
		ERRORLOG("setnonblock error");
		return -1;
	}
	return 0;
}

ssize_t net_tcp::Sendto(int sockfd, const void *buf, size_t len, int flags, 
               const struct sockaddr * to, int tolen)
{
	ssize_t send_result = sendto(sockfd, buf, len, flags, to, tolen);
	if(send_result == -1)
	{
		ERRORLOG("send broadcast msg error");
	}
	return send_result;
}

/*发送广播*/
ssize_t net_com::SendBroadcastMsg(const std::string &msg)
{
	int iOptval = 1;
	struct sockaddr_in Addr;
	/*创建socket*/
	int sockfd = net_tcp::Socket(AF_INET, SOCK_DGRAM, 0);
	/*setsockopt*/
	Setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &iOptval, sizeof(int));
	memset(&Addr, 0, sizeof(struct sockaddr_in));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    Addr.sin_port = htons(8899);
	/*send broadcast msg*/
	ssize_t send_value = Sendto(sockfd, msg.data(), msg.size(), 0, (struct sockaddr *)&Addr, sizeof(struct sockaddr));
	return send_value;
}

/*接收广播数据*/
void net_com::RecvfromBroadcastMsg()
{
	int iOptval = 1;
	char rgMessage[1024*10] = {0}; 
	struct sockaddr_in Addr;
	/*创建socket*/
	int sockfd = net_tcp::Socket(AF_INET, SOCK_DGRAM, 0);
	/*setsockopt*/
	Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &iOptval, sizeof(int));
	memset(&Addr, 0, sizeof(struct sockaddr_in));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = INADDR_ANY;
    Addr.sin_port = htons(8899);
	socklen_t iAddrLength = sizeof(Addr);
	if (bind(sockfd, (struct sockaddr *)&Addr, sizeof(Addr)) == -1)
    {
		ERRORLOG("bind failed!");
    }
	/*recvfrom broadcast msg*/
	while(1)
	{
	    int recvfrom_value = recvfrom(sockfd, rgMessage, sizeof(rgMessage), 0, (struct sockaddr *)&Addr, &iAddrLength);
		if(recvfrom_value == -1)
        {
			ERRORLOG("recv failed!");
        }
		std::string str = std::string((char *)rgMessage, recvfrom_value);
		CommonMsg commonmsg;
		commonmsg.ParseFromString(str);

		BroadcastNodeReq broadcastNodeReq;
		broadcastNodeReq.ParseFromString(commonmsg.data());

		if( 0 != Util::IsVersionCompatible( commonmsg.version() ) )
		{
			INFOLOG("version is not Compatible");
			continue ;
		}

		NodeInfo *nodeinfo = broadcastNodeReq.mutable_mynode();
		
		//获取自身节点
		auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();

		Node node;
		//node.fd             = -1;
		node.id             = nodeinfo->node_id();
		node.local_ip       = nodeinfo->local_ip();
		node.local_port     = nodeinfo->local_port();
		node.public_ip      = nodeinfo->public_ip();
		node.public_port    = nodeinfo->public_port();
		//node.conn_kind      = NOTYET;
		node.mac_md5        = nodeinfo->mac_md5();
		node.is_public_node = nodeinfo->is_public_node();
		node.fee			= nodeinfo->fee();
		node.package_fee	= nodeinfo->package_fee();
		node.base58address  = nodeinfo->base58addr();
		node.public_node_id = nodeinfo->public_node_id();
		node.chain_height   = nodeinfo->chain_height();

		//根据节点id，从k桶中查找
		Node tmp_node;
		bool find = Singleton<PeerNode>::get_instance()->find_node(node.id,tmp_node);
		if(!self_node.is_public_node && (node.local_port == self_node.local_port))
		{
			if(node.conn_kind == NOTYET && !node.is_public_node)
	        {
				node.conn_kind      = DRTI2I;
				if(self_node.id != node.id)
				{
					if(find && tmp_node.fd > 0)
					{
						node.fd = tmp_node.fd;
						Singleton<PeerNode>::get_instance()->update(node);
					}
					else if(!find && self_node.id != node.id)
					{
						Singleton<PeerNode>::get_instance()->add(node);
					}
				}
				if(!node.is_public_node && self_node.id != node.id && !find)
				{
					Singleton<PeerNode>::get_instance()->update(node);
					//Singleton<PeerNode>::get_instance()->add(node);
				}
			}

			if(!node.is_public_node && self_node.id != node.id)
			{
				DEBUGLOG("node.local_ip: {}", IpPort::ipsz(node.local_ip));
				int cfd = connect_init(node.local_ip, node.local_port);
				if (cfd <= 0)
				{
					continue;
				}
				node.fd = cfd;
				Singleton<PeerNode>::get_instance()->update(node);
				Singleton<BufferCrol>::get_instance()->add_buffer(node.local_ip, node.local_port, cfd);
				Singleton<EpollMode>::get_instance()->add_epoll_event(cfd, EPOLLIN | EPOLLET);
				net_com::SendConnectNodeReq(node);
			}
		}	
	}
}

int net_com::connect_init(u32 u32_ip, u16 u16_port)
{
	int confd = 0;
	struct sockaddr_in servaddr = {0};
	struct sockaddr_in my_addr = {0};
	int ret = 0;

	confd = Socket(AF_INET, SOCK_STREAM, 0);
	int flags = 1;
	Setsockopt(confd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(int));
	flags = 1;
	Setsockopt(confd, SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(int));

	// 绑定端口
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVERMAINPORT);

	ret = bind(confd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
	if (ret < 0)
		ERRORLOG("bind hold port");

	//连接对方
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(u16_port);
	struct in_addr addr = {0};
	memcpy(&addr, &u32_ip, sizeof(u32_ip));
	inet_pton(AF_INET, inet_ntoa(addr), &servaddr.sin_addr);

	/*阻塞情况下linux系统默认超时时间为75s*/
	if (set_fd_noblocking(confd) < 0)
	{
		DEBUGLOG("setnonblock error");
		return -1;
	}

	ret = Connect(confd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	if (ret != 0)
	{
		if (errno == EINPROGRESS)
		{
			DEBUGLOG("Doing connection.");
			struct epoll_event newPeerConnectionEvent;
			int epollFD = -1;
			struct epoll_event processableEvents;
			unsigned int numEvents = -1;

			if ((epollFD = epoll_create(1)) == -1)
			{
				ERRORLOG("Could not create the epoll FD list!");
				close(confd);
				return -1;
			}     

			newPeerConnectionEvent.data.fd = confd;
			newPeerConnectionEvent.events = EPOLLOUT | EPOLLIN | EPOLLERR;

			if (epoll_ctl(epollFD, EPOLL_CTL_ADD, confd, &newPeerConnectionEvent) == -1)
			{
				ERRORLOG("Could not add the socket FD to the epoll FD list!");
				close(confd);
				close(epollFD);
				return -1;
			}

			numEvents = epoll_wait(epollFD, &processableEvents, 1, 3*1000);

			if (numEvents < 0)
			{
				ERRORLOG("Serious error in epoll setup: epoll_wait () returned < 0 status!");
				close(epollFD);
				close(confd);
				return -1;
			}
			int retVal = -1;
			socklen_t retValLen = sizeof (retVal);
			if (getsockopt(confd, SOL_SOCKET, SO_ERROR, &retVal, &retValLen) < 0)
			{
				ERRORLOG("getsockopt SO_ERROR error!");
				close(confd);
				close(epollFD);
				return -1;
			}

			if (retVal == 0)  //成功
			{
				close(epollFD);
				return confd;
			} 
			else
			{
				// ERRORLOG("getsockopt SO_ERROR retVal error : %s", strerror(retVal));
				close(epollFD);
				close(confd);
				return -1;
			}	
		}
		else
		{
			// ERRORLOG("not EINPROGRESS: %s", strerror(errno));
			close(confd);
			return -1;			
		}
	}

	return confd;
}


bool net_com::send_one_message(const Node &to, const net_pack &pack)
{
	auto msg = Pack::packag_to_str(pack);
	uint8_t priority = pack.flag & 0xF;

	return send_one_message(to, msg, priority);
}

bool net_com::send_one_message(const Node &to, const std::string &msg, const int8_t priority)
{
	INFOLOG("send_one_message");
	DEBUGLOG("to.conn_kind: {}", to.conn_kind);
	DEBUGLOG("to.public_ip: {}", IpPort::ipsz(to.public_ip));

	MsgData send_data;
	send_data.type = E_WRITE;
	send_data.fd = to.fd;
	send_data.ip = to.public_ip;
	send_data.port = to.public_port;

	// if (to.is_public_node && IpPort::is_public_ip(to.public_ip) == false)
	// {
	// 	// 阻止公网配置为内网节点时的循环转发
	// 	return false;
	// }
	
	if (net_com::is_need_send_trans_message(to))
	{
		net_com::SendTransMsgReq(to, msg, priority);
		return true;
	}
	else
	{
		Singleton<BufferCrol>::get_instance()->add_buffer(send_data.ip, send_data.port, send_data.fd);
		Singleton<BufferCrol>::get_instance()->add_write_pack(send_data.ip, send_data.port, msg);
		bool bRet = global::queue_write.push(send_data);
		return bRet;
	}
}

bool net_com::send_one_message(const MsgData& to, const net_pack &pack)
{
	MsgData send_data;
	send_data.type = E_WRITE;
	send_data.fd = to.fd;
	send_data.ip = to.ip;
	send_data.port = to.port;

	auto msg = Pack::packag_to_str(pack);	
	Singleton<BufferCrol>::get_instance()->add_buffer(send_data.ip, send_data.port, send_data.fd);
	Singleton<BufferCrol>::get_instance()->add_write_pack(send_data.ip, send_data.port, msg);
	bool bRet = global::queue_write.push(send_data);
	return bRet;
}


uint64_t net_data::pack_port_and_ip(uint16_t port, uint32_t ip)
{
	uint64_t ret = port;
	ret = ret << 32 | ip;
	return ret;
}

uint64_t net_data::pack_port_and_ip(int port, std::string ip)
{
	uint64_t ret = port;
	uint32_t tmp;
	inet_pton(AF_INET, ip.c_str(), &tmp);
	ret = ret << 32 | tmp;
	return ret;
}
std::pair<uint16_t, uint32_t> net_data::apack_port_and_ip_to_int(uint64_t port_and_ip)
{
	uint64_t tmp = port_and_ip;
	uint32_t ip = tmp << 32 >> 32;
	uint16_t port = port_and_ip >> 32;
	return std::pair<uint16_t, uint32_t>(port, ip);
}
std::pair<int, std::string> net_data::apack_port_and_ip_to_str(uint64_t port_and_ip)
{
	uint64_t tmp = port_and_ip;
	uint32_t ip = tmp << 32 >> 32;
	uint16_t port = port_and_ip >> 32;
	char buf[100];
	inet_ntop(AF_INET, (void *)&ip, buf, 16);
	return std::pair<uint16_t, std::string>(port, buf);
}

int net_data::get_mac_info(vector<string> &vec)
{
	int fd;
	int interfaceNum = 0;
	struct ifreq buf[16] = {0};
	struct ifconf ifc;
	char mac[16] = {0};

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		ERRORLOG("socket");

		close(fd);
		return -1;
	}
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;
	if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
	{
		interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
		while (interfaceNum-- > 0)
		{
			if (string(buf[interfaceNum].ifr_name) == "lo")
			{
				continue;
			}
			if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
			{
				memset(mac, 0, sizeof(mac));
				snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],

						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
						 (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);
				// allmac[i++] = mac;
				std::string s = mac;
				vec.push_back(s);
			}
			else
			{
				ERRORLOG("ioctl: {}", strerror(errno));
				close(fd);
				return -1;
			}
		}
	}
	else
	{
		ERRORLOG("ioctl: {}", strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

std::string net_data::get_mac_md5()
{
	std::vector<string> vec;
	std::string data;
	net_data::get_mac_info(vec);
	for (auto it = vec.begin(); it != vec.end(); ++it)
	{
		DEBUGLOG("get mac: {}", *it);
		data += *it;
	}
	string md5 = getMD5hash(data);
	DEBUGLOG("get mac md5: {}", md5);

	return md5;
}


int net_com::parse_conn_kind(Node &to)
{
	auto self = Singleton<PeerNode>::get_instance()->get_self_node();

	if (Singleton<Config>::get_instance()->GetIsPublicNode())
	{
		if (to.is_public_node == true)
		{
			to.conn_kind = DRTO2O; //外外直连
		}
		else if (to.is_public_node == false)
		{
			//to.conn_kind = DRTO2I; //外转内直连
		}
		else
		{
			DEBUGLOG("Public Ip connect error!");
			to.conn_kind = BYSERV;
			return -1;
		}
	}
	else if (!Singleton<Config>::get_instance()->GetIsPublicNode())
	{
		if (to.is_public_node == true)
		{
			to.conn_kind = DRTI2O; //内外直连
		}
		//在同一个局域网
		else if ((self.public_ip == to.public_ip && self.local_ip != to.local_ip) || (strncmp(IpPort::ipsz(self.public_ip), "192", 3) == 0 && strncmp(IpPort::ipsz(to.public_ip), "192", 3) == 0 && self.local_ip != to.local_ip) ||
				 (strncmp(IpPort::ipsz(to.public_ip), "192", 3) == 0 && self.local_ip != to.local_ip))
		{
			to.conn_kind = DRTI2I; //内内直连
		}
		else if (to.is_public_node == false)
		{
			to.conn_kind = BYSERV; //内内打洞
		}
		else
		{
			DEBUGLOG("Local Ip connect error!");
			to.conn_kind = BYSERV;
			return -1;
		}
	}
	else
	{
		DEBUGLOG("unknwon conn_kind error!");
		to.conn_kind = BYSERV;
		return -1;
	}
    
	return to.conn_kind;
}



bool net_com::is_need_send_trans_message(const Node & to)
{
	Node node;
	bool isFind = Singleton<PeerNode>::get_instance()->find_node(to.id, node);
	auto self_node  = Singleton<PeerNode>::get_instance()->get_self_node();
	
	if ( isFind )
	{
		if ((to.conn_kind != NOTYET && to.conn_kind != BYSERV))
		{
			// 找到，并且不是未连接或是转发，可直连发送
			return false;
		}
		else
		{
			// 找到，需要转发
			return true;
		}
	}
	else
	{
		if (to.public_node_id.empty())
		{
			//  无连接公网转发服务器，一般是需要第一次连接
			if (to.local_ip != 0)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
		else
		{
			// 依靠公网转发无法看到的节点
			return true;
		}
	}
}

// 读取id文件
bool read_id_file()
{
	DEBUGLOG(YELLOW "read_id_file start" RESET);
	std::string strID = Singleton<Config>::get_instance()->GetKID();
	DEBUGLOG(YELLOW "read_id_file string strID({})" RESET, strID.c_str());
	if (strID == "")
	{
		Singleton<PeerNode>::get_instance()->make_rand_id();
		Singleton<Config>::get_instance()->SetKID(
			Singleton<PeerNode>::get_instance()->get_self_id()
		);
	}
	else
	{
		Singleton<PeerNode>::get_instance()->set_self_id(strID);
	}
	DEBUGLOG(YELLOW "read_id_file end" RESET);
	return true;
}

void handle_pipe(int sig)
{
	//啥也不做
}

bool net_com::net_init()
{
	//获取当前CPU核心数
	global::cpu_nums = sysconf(_SC_NPROCESSORS_ONLN);
	INFOLOG("当前cpu核心数：{}", global::cpu_nums);

	//设置随机数种子
	uint32_t seed[1] = {0};
	srand((unsigned long)seed);

	//捕捉SIGPIPE信号，防止程序意外退出
	struct sigaction sa;
	sa.sa_handler = handle_pipe;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);

	//阻塞SIGPIPE信号
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigprocmask(SIG_BLOCK, &set, NULL);

	//忽略SIGPIPE信号
	signal(SIGPIPE, SIG_IGN);

	//获取本机所有mac地址的MD5值
	global::mac_md5 = net_data::get_mac_md5();
	Singleton<PeerNode>::get_instance()->set_self_mac_md5(global::mac_md5);

	//打开防火墙端口
	char buf[1024] = {0};
	sprintf(buf, "firewall-cmd --add-port=%hu/tcp", SERVERMAINPORT);
	system(buf);

	char udpbuf[1024] = {0};
	sprintf(udpbuf, "firewall-cmd --add-port=%hu/udp", 8899);
	system(udpbuf);

	//注册回调函数
	Singleton<ProtobufDispatcher>::get_instance()->registerAll();

	// 得到K桶刷新时间
	global::nodelist_refresh_time = Singleton<Config>::get_instance()->GetVarInt("k_refresh_time");
	global::local_ip = Singleton<Config>::get_instance()->GetVarString("local_ip");

	if (global::nodelist_refresh_time <= 0)
	{
		global::nodelist_refresh_time = K_REFRESH_TIME;
	}

	// 自己 ID
	if (false == read_id_file())
	{
		DEBUGLOG("创建或者读取自己ID失败");
		return false;
	}

	// 获取本机内网IP
	if (global::local_ip == "")
	{
		// INFOLOG("内网IP为空,开始查找内网IP:");
		if (false == IpPort::get_localhost_ip())
		{
			DEBUGLOG("获取本机内网ip失败");
			return false;
		}
	}
	else
	{
		INFOLOG("内网不为空");

        if(!Singleton<Config>::get_instance()->GetIsPublicNode())
        {
			if (false == IpPort::get_localhost_ip())
			{
					DEBUGLOG("获取本机内网ip失败");
					return false;
			}
        }
        if(Singleton<Config>::get_instance()->GetIsPublicNode())
        {
            Singleton<PeerNode>::get_instance()->set_self_ip_l(IpPort::ipnum(global::local_ip.c_str()));
            Singleton<PeerNode>::get_instance()->set_self_port_l(SERVERMAINPORT);
			Singleton<PeerNode>::get_instance()->set_self_ip_p(IpPort::ipnum(global::local_ip.c_str()));
			Singleton<PeerNode>::get_instance()->set_self_port_p(SERVERMAINPORT);
		}
	}
	//设置本机是否为公网节点
	Singleton<PeerNode>::get_instance()->set_self_public_node(Singleton<Config>::get_instance()->GetIsPublicNode());

	// 工作线程池启动
	Singleton<WorkThreads>::get_instance()->start();

	// 创建监听线程
	Singleton<EpollMode>::get_instance()->start();
	
	//获取自身节点信息
	//bool is_public_node_value = Singleton<Config>::get_instance()->GetIsPublicNode();

	//启动获取nodelist线程
	//if(is_public_node_value){
    Singleton<PeerNode>::get_instance()->nodelist_refresh_thread_init();
	//}

	// 启动心跳
	global::g_timer.AsyncLoop(HEART_INTVL * 1000, net_com::DealHeart);

    global::registe_public_node_timer.AsyncLoop(12 * 60 * 60 * 1000,net_com::RegisteToPublic);//liuzg
	
	//启动广播程序
	global::broadcast_timer.AsyncLoop(30 * 1000, net_com::SendBroadcastNodeReq);
    //global::registe_public_node_timer.AsyncLoop(5 * 60 * 1000,net_com::RegisteToPublic);//liuzg
	//启动广播数据接收线程
	handleBroadcastMsgThread();

	Singleton<NodeCache>::get_instance()->timer_start();

	return true;
}

void net_com::RegisteToPublic() //liuzg
{
	INFOLOG("RegisteToPublic");
	auto node = Singleton<PeerNode>::get_instance()->get_self_node();
	bool is_public = node.is_public_node ;
	if(!is_public && global::queue_work.IsEmpty())
	{
		vector<Node> vec = Singleton<PeerNode>::get_instance()->get_public_node();
		if (vec.size() == 1)
		{
			return;
		}

		auto ite = vec.begin(); 
		for(; ite!= vec.end(); ite++)
		{ 
			if(node.public_node_id == (*ite).id) 
			{      
		        Singleton<PeerNode>::get_instance()->delete_node((*ite).id);
				vec.erase(ite);
				break;
			}
		}
		int num = vec.size();
		if(num != 0)
		{
			srand((int)time(0));       
			int mod = rand() % num;
			net_com::SendRegisterNodeReq(vec[mod], true);       
			Singleton<PeerNode>::get_instance()->set_self_public_node_id(vec[mod].id);
		}
	} 
}


// 测试单发信息
int net_com::input_send_one_message()
{
	DEBUGLOG(RED "input_send_one_message start" RESET);
	string id;
	cout << "please input id:";
	cin >> id;

	while (true)
	{
		//验证id是否合法
		bool result = Singleton<PeerNode>::get_instance()->is_id_valid(id);
		if (false == result)
		{
			cout << "invalid id , please input id:";
			cin >> id;
			continue;
		}
		else
		{
			break;
		}
	};

	string msg;
	cout << "please input msg:";
	cin >> msg;

	int num;
	cout << "please input num:";
	cin >> num;

	bool bl;
	for (int i = 0; i < num; ++i)
	{
		bl = net_com::SendPrintMsgReq(id, msg);

		if (bl)
		{
			printf("第 %d 次发送成功\n", i + 1);
		}
		else
		{
			printf("第 %d 次发送失败\n", i + 1);
		}

	}
	return bl ? 0 : -1;
}

bool net_com::handleBroadcastMsgThread()
{
	std::thread broadcast_thread = std::thread(std::bind(&net_com::RecvfromBroadcastMsg));
	broadcast_thread.detach();
	return true;
}

// 测试广播信息
int net_com::test_broadcast_message()
{
	string str_buf = "Hello World!";

	PrintMsgReq printMsgReq;
	printMsgReq.set_data(str_buf);

	net_com::broadcast_message(printMsgReq);
	return 0;
}


bool net_com::test_send_big_data()
{
	string id;
	cout << "please input id:";
	cin >> id;
	auto is_vaild = [](string id_str) {
		int count = 0;
		for (auto i : id_str)
		{
			if (i != '1' || i != '0')
				return false;
			count++;
		}
		return count == 16;
	};
	while (is_vaild(id))
	{
		cout << "invalid id , please input id:";
		cin >> id;
	};
	Node tmp_node;
	if (!Singleton<PeerNode>::get_instance()->find_node(id_type(id), tmp_node))
	{
		DEBUGLOG("invaild id, not in my peer node");
		return false;
	}
	string tmp_data;
	int txtnum;
	cout << "please input test byte num:";
	cin >> txtnum;
	for (int i = 0; i < txtnum; i++)
	{
		char x, s;									  //x表示这个字符的ascii码 ，s表示这个字符的大小写
		s = (char)rand() % 2;						  //随机使s为1或0，为1就是大写，为0就是小写
		if (s == 1)									  //如果s=1
			x = (char)rand() % ('Z' - 'A' + 1) + 'A'; //将x赋为大写字母的ascii码
		else
			x = (char)rand() % ('z' - 'a' + 1) + 'a'; //如果s=0，x赋为小写字母的ascii码
		tmp_data.push_back(x);						  //将x转换为字符输出
	}
	tmp_data.push_back('z');
	tmp_data.push_back('z');
	tmp_data.push_back('z');
	tmp_data.push_back('z');
	tmp_data.push_back('z');


	net_com::SendPrintMsgReq(tmp_node, tmp_data, 1);
	return true;
}

void net_com::InitRegisterNode()
{
	vector<Node> nodelist;
	auto serverlist = Singleton<Config>::get_instance()->GetServerList();
	for (auto server : serverlist)
	{
		Node node;
		std::string ip = std::get<0>(server);
		int port = std::get<1>(server);
		node.local_ip = IpPort::ipnum(ip);
		node.public_ip = IpPort::ipnum(ip);
		node.local_port = port;
		node.public_port = port;
	
		node.is_public_node = true;
		if (ip.size() > 0 && ip != global::local_ip)
		{
			nodelist.push_back(node);
		}
	}
	
	if (nodelist.size() == 0)
	{
		return;
	}

	const Node & selfNode = Singleton<PeerNode>::get_instance()->get_self_node();
	if (selfNode.is_public_node == false)
	{
		// 内网节点
		std::random_shuffle(nodelist.begin(), nodelist.end());
		Node tempNode = nodelist[0];
		nodelist.clear();
		nodelist.push_back(tempNode);
	}

	for (auto & node : nodelist)
	{	
		DEBUGLOG("public ip:{}", IpPort::ipsz(node.public_ip));
		if (node.is_public_node)
		{
			net_com::SendRegisterNodeReq(node, true);
		}
	}
}

bool net_com::SendPrintMsgReq(Node &to, const std::string data, int type)
{
	PrintMsgReq printMsgReq;
	printMsgReq.set_data(data);
	printMsgReq.set_type(type);
	net_com::send_message(to, printMsgReq);
	return true;
}

bool net_com::SendPrintMsgReq(const std::string & id, const std::string data, int type)
{
	PrintMsgReq printMsgReq;
	printMsgReq.set_data(data);
	printMsgReq.set_type(type);
	net_com::send_message(id, printMsgReq);
	return true;
}


bool net_com::SendRegisterNodeReq(Node& dest, bool get_nodelist)
{
	INFOLOG("SendRegisterNodeReq");
	RegisterNodeReq getNodes;
	getNodes.set_is_get_nodelist(get_nodelist);
	NodeInfo* mynode = getNodes.mutable_mynode();
	const Node & selfNode = Singleton<PeerNode>::get_instance()->get_self_node();

	DEBUGLOG("SendRegisterNodeReq selfNode.port:{}", selfNode.public_port);
	DEBUGLOG("SendRegisterNodeReq selfNode.ip:{}", IpPort::ipsz(selfNode.public_ip));

	mynode->set_local_ip( selfNode.local_ip);
	mynode->set_local_port( selfNode.local_port);
	mynode->set_public_ip( selfNode.public_ip);
	mynode->set_public_port( selfNode.public_port);
	mynode->set_is_public_node(Singleton<Config>::get_instance()->GetIsPublicNode());
	mynode->set_mac_md5(global::mac_md5);

	auto self_id = Singleton<PeerNode>::get_instance()->get_self_id();
	mynode->set_node_id(self_id);
	mynode->set_fee( selfNode.fee );
	mynode->set_package_fee(selfNode.package_fee);
	mynode->set_base58addr(selfNode.base58address );
	mynode->set_chain_height(Singleton<PeerNode>::get_instance()->get_self_chain_height_newest());

	u32 dest_ip = dest.public_ip;
	u16 port = dest.public_port;
	int fd = dest.fd;
	
	if (fd > 0)
	{
		net_com::send_message(dest, getNodes, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
		return true;
	}
	else
	{
		int cfd = connect_init(dest_ip, port);
		if (cfd <= 0)
		{
			return false;
		}

		dest.fd = cfd;
		DEBUGLOG("SendRegisterNodeReq dest.fd:{}", dest.fd);
		net_com::parse_conn_kind(dest);
		if(!selfNode.is_public_node && dest.is_public_node)
		{
			Node temp_node;
			bool find_result = Singleton<PeerNode>::get_instance()->find_node(dest.id, temp_node);
			if(find_result)
			{
				Singleton<PeerNode>::get_instance()->update(dest);
				Singleton<PeerNode>::get_instance()->update_public_node(dest);
			}
			
		}
		Singleton<BufferCrol>::get_instance()->add_buffer(dest_ip, port, cfd);
		Singleton<EpollMode>::get_instance()->add_epoll_event(cfd, EPOLLIN | EPOLLET);

		net_com::send_message(dest, getNodes, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
	}

	return true;
}


void net_com::SendConnectNodeReq(Node& dest)
{
	ConnectNodeReq connectNodeReq;

	NodeInfo* mynode = connectNodeReq.mutable_mynode();
	mynode->set_local_ip( Singleton<PeerNode>::get_instance()->get_self_node().local_ip);
	mynode->set_local_port( Singleton<PeerNode>::get_instance()->get_self_node().local_port);
	// mynode->set_public_ip( Singleton<PeerNode>::get_instance()->get_self_node().public_ip);
	// mynode->set_public_port( Singleton<PeerNode>::get_instance()->get_self_node().public_port);
	mynode->set_is_public_node(Singleton<Config>::get_instance()->GetIsPublicNode());
	mynode->set_mac_md5(global::mac_md5);
	mynode->set_conn_kind(dest.conn_kind);
	mynode->set_fee(Singleton<PeerNode>::get_instance()->get_self_node().fee);
	mynode->set_package_fee(Singleton<PeerNode>::get_instance()->get_self_node().package_fee);
	mynode->set_base58addr( Singleton<PeerNode>::get_instance()->get_self_node().base58address );
	mynode->set_chain_height(Singleton<PeerNode>::get_instance()->get_self_chain_height_newest());

	auto self_id = Singleton<PeerNode>::get_instance()->get_self_id();
	mynode->set_node_id(self_id);
	mynode->set_public_node_id(Singleton<PeerNode>::get_instance()->get_self_node().public_node_id);
	if(dest.conn_kind == BYSERV)
	{
		CommonMsg msg;
		Pack::InitCommonMsg(msg, connectNodeReq);

		net_pack pack;
		Pack::common_msg_to_pack(msg, 0, pack);
		int8_t priority = pack.flag & 0xF;
		auto msg1 = Pack::packag_to_str(pack);
		net_com::SendTransMsgReq(dest, msg1, priority);
	}
	else
	{
		net_com::send_message(dest, connectNodeReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
	}
}


void net_com::SendBroadcastNodeReq()
{
	BroadcastNodeReq broadcastNodeReq;

	NodeInfo* mynode = broadcastNodeReq.mutable_mynode();
	auto self_id = Singleton<PeerNode>::get_instance()->get_self_id();
    auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();

	mynode->set_local_ip( self_node.local_ip);
	mynode->set_local_port( self_node.local_port); // 广播仅用内内直连，使用内网IP
	mynode->set_public_ip( self_node.local_ip);
	mynode->set_public_port( self_node.local_port);  // 广播仅用内内直连，使用内网端口
	mynode->set_is_public_node(Singleton<Config>::get_instance()->GetIsPublicNode());
	mynode->set_mac_md5(global::mac_md5);
	//mynode->set_conn_kind(dest.conn_kind);
	mynode->set_fee(self_node.fee);
	mynode->set_package_fee(self_node.package_fee);
	mynode->set_base58addr( self_node.base58address);
	mynode->set_node_id(self_id);
	mynode->set_public_node_id(self_node.public_node_id);
	mynode->set_chain_height(self_node.chain_height);
    //组装数据
	CommonMsg msg;
	net_pack pack;
	Pack::InitCommonMsg(msg, broadcastNodeReq);
	auto msg1 = msg.SerializeAsString();
	//开始广播数据
	if(!self_node.is_public_node)
	{
		ssize_t send_value = SendBroadcastMsg(msg1);
		if(send_value > 0)
		{
			DEBUGLOG("send broadcast message success");
		}
	}
	
	//net_com::SendTransMsgReq(dest, msg1);
}


void net_com::SendTransMsgReq(Node dest, const std::string msg, const int8_t priority)
{
	INFOLOG("SendTransMsgReq");
	TransMsgReq transMsgReq;

	NodeInfo* destnode = transMsgReq.mutable_dest();
	destnode->set_node_id(dest.id);
	destnode->set_public_node_id(dest.public_node_id);
	transMsgReq.set_data(msg);
	transMsgReq.set_priority(priority);

	DEBUGLOG("SendTransMsgReq: trans msg to public id:{}", destnode->public_node_id());
	
	//获取自身节点连接的公网节点ID，即根据public_node_id取出相应的公网节点node
	auto self = Singleton<PeerNode>::get_instance()->get_self_node();

	if (self.is_public_node)
	{
		Node publicNode;
		if (! Singleton<PeerNode>::get_instance()->find_node(dest.public_node_id, publicNode))
		{
			DEBUGLOG("SendTransMsgReq failed");
			return ;
		}

		net_com::send_message(publicNode, transMsgReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, (net_com::Priority)priority);
	}
	else
	{
		//根据self.public_node_id获取连接的公网节点node信息
		Node server_node;
		auto find = Singleton<PeerNode>::get_instance()->find_node(self.public_node_id, server_node);
		if(find)
		{
			net_com::send_message(server_node, transMsgReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, (net_com::Priority)priority);
			return;
		}
	}
	
	return;
}

void net_com::SendNotifyConnectReq(const Node& dest)
{
	NotifyConnectReq notifyConnectReq;

	NodeInfo* server_node = notifyConnectReq.mutable_server_node();
	server_node->set_node_id(Singleton<PeerNode>::get_instance()->get_self_node().id);
	server_node->set_local_ip( Singleton<PeerNode>::get_instance()->get_self_node().local_ip);
	server_node->set_local_port( Singleton<PeerNode>::get_instance()->get_self_node().local_port);
	server_node->set_public_ip( Singleton<PeerNode>::get_instance()->get_self_node().public_ip);
	server_node->set_public_port( Singleton<PeerNode>::get_instance()->get_self_node().public_port);	
	server_node->set_is_public_node(Singleton<Config>::get_instance()->GetIsPublicNode());
	server_node->set_mac_md5(global::mac_md5);
	server_node->set_fee(Singleton<PeerNode>::get_instance()->get_self_node().fee);
	server_node->set_package_fee(Singleton<PeerNode>::get_instance()->get_self_node().package_fee);
	server_node->set_base58addr( Singleton<PeerNode>::get_instance()->get_self_node().base58address );
	server_node->set_public_node_id(Singleton<PeerNode>::get_instance()->get_self_node().id);
	server_node->set_chain_height(Singleton<PeerNode>::get_instance()->get_self_chain_height_newest());

	NodeInfo* client_node = notifyConnectReq.mutable_client_node();
	client_node->set_node_id(dest.id);

	vector<Node> nodelist = Singleton<PeerNode>::get_instance()->get_nodelist(NODE_PUBLIC,true);
	for(auto node:nodelist)
	{
		net_com::send_message(node, notifyConnectReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
	}
}

void net_com::SendPingReq(const Node& dest)
{
	PingReq pingReq;
	pingReq.set_id(Singleton<PeerNode>::get_instance()->get_self_id());
	net_com::send_message(dest, pingReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
}

void net_com::SendPongReq(const Node& dest)
{
	PongReq pongReq;
	pongReq.set_id(Singleton<PeerNode>::get_instance()->get_self_id());

	uint32 chainHeight = net_callback::chain_height_callback();
	pongReq.set_chain_height(chainHeight);
	Singleton<PeerNode>::get_instance()->set_self_chain_height(chainHeight);

	net_com::send_message(dest, pongReq, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
}

void net_com::DealHeart()
{
	Node mynode = Singleton<PeerNode>::get_instance()->get_self_node();
	vector<Node> nodelist = Singleton<PeerNode>::get_instance()->get_nodelist();

	for(auto &node:nodelist)
	{
		if(mynode.is_public_node)
		{
			node.heart_time -= HEART_INTVL;
			node.heart_probes -= 1;
			if(node.heart_probes <= 0)
			{
				DEBUGLOG("DealHeart delete node: {}", node.id);

				Singleton<PeerNode>::get_instance()->delete_node(node.id);
			}
			else
			{
				net_com::SendPingReq(node);
			}
			Singleton<PeerNode>::get_instance()->update(node);
			if(node.is_public_node)
			{
				Singleton<PeerNode>::get_instance()->update_public_node(node);
			}
		}
	}	
}

bool net_com::SendSyncNodeReq(const Node& dest)
{
	INFOLOG("SendSyncNodeReq");
	SyncNodeReq syncNodeReq;
	//获取自身节点信息
	auto self_node = Singleton<PeerNode>::get_instance()->get_self_node();
	vector<Node> && nodelist = Singleton<PeerNode>::get_instance()->get_sub_nodelist(self_node.id);
	vector<Node> && publicNodeList = Singleton<PeerNode>::get_instance()->get_public_node();
	nodelist.insert(nodelist.end(), publicNodeList.begin(), publicNodeList.end());
	
	if(nodelist.size() == 0)
	{
		return false;
	}
	//存储自身节点ID
	syncNodeReq.add_ids(std::move(self_node.id));
	//将连接自己的内网节点放入syncNodeReq发送给对方
	for(auto& node:nodelist)
	{	
		if(node.is_public_node && node.fd < 0) //liuzg
		{
              continue;
		}
		if(g_testflag == 0 && node.is_public_node)   //liuzg
		{
			u32 & localIp = node.local_ip;
			u32 & publicIp = node.public_ip;

			if (localIp != publicIp || IpPort::is_public_ip(localIp) == false)
			{
				continue;
			}
		}		

		NodeInfo* nodeinfo = syncNodeReq.add_nodes();
        //syncNodeReq.add_ids(std::move(node.id));
		nodeinfo->set_node_id(node.id);
		nodeinfo->set_local_ip( node.local_ip);
		nodeinfo->set_local_port( node.local_port);
		nodeinfo->set_public_ip( node.public_ip);
		nodeinfo->set_public_port( node.public_port);			
		nodeinfo->set_is_public_node(node.is_public_node);
		nodeinfo->set_mac_md5(std::move(node.mac_md5));
		nodeinfo->set_fee(node.fee);
		nodeinfo->set_package_fee(node.package_fee);	
		nodeinfo->set_base58addr(node.base58address);
		nodeinfo->set_chain_height(node.chain_height);
		nodeinfo->set_public_node_id(node.public_node_id);
		
	}
	return net_com::send_message(dest, syncNodeReq, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
}


void net_com::SendGetHeightReq(const Node& dest, bool is_fetch_public)
{
	GetHeightReq heightReq;
	heightReq.set_id(Singleton<PeerNode>::get_instance()->get_self_id());
	heightReq.set_is_fetch_public(is_fetch_public);
	net_com::send_message(dest, heightReq);
}

namespace net_callback
{
	std::function<unsigned int(void)> chain_height_callback;
}

void net_callback::register_chain_height_callback(std::function<unsigned int(void)> callback)
{
	net_callback::chain_height_callback = callback;
}
