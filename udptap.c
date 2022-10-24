#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef __NetBSD__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>

#include <sys/select.h>

#include <time.h>
#include <mcrypt.h>
#include <cotp.h>
#include <sys/random.h>

#include <baseencode.h>

#define MAX_DATA_LEN 1526

#pragma pack(push, 1)
typedef struct stPacket
{
    unsigned int uiRand;
    unsigned int uiCRC32;
    unsigned short usLen;
    unsigned char ucBuf[MAX_DATA_LEN];
} Packet, *PPacket;
#pragma pack(pop)

typedef enum _crypt_error
{
    CRYPT_SUCCESS = 0,
    CRYPT_INVALID_TOTP_COUNT = 1,
    CRYPT_DECRYPT_FAILED = 2,
    CRYPT_KEYSIZE_INVALID = 3,
    CRYPT_RANDOM_FAILED = 4,
    CRYPT_ENCRYPT_FAILED = 5,
    CRYPT_BLK_NOTFIT = 6,
    CRYPT_TOTP_FAILED = 7,
} crypt_error_t;

FILE *fhLog;

crypt_error_t encryptDataTOTP(MCRYPT td, unsigned char ucPasswd[22], unsigned char *lpucBuf, unsigned int *lpuiBufLen, time_t now, unsigned int uiPeriod, char *lpBase32SecretSeed)
{
    //printf("**********************************************************\n");
    int iRes = 0;
    cotp_error_t err;
    unsigned char ucPasswdBuf[32] = {0};
    int iKeysize = 0;
    int iBlocksize = 0;
    int iCnt;
    char *lpszTOTP;

    //printf("*lpuiBufLen: %d\n", *lpuiBufLen);
    iBlocksize = mcrypt_enc_get_block_size(td);
    iCnt = ((*lpuiBufLen - 1) / iBlocksize + 1) * iBlocksize;  // pad to block size
    //printf("encryptDataTOTP iCnt: %d\n", iCnt);
    if (iCnt > sizeof(Packet))
    {
        return CRYPT_BLK_NOTFIT;
    }

    lpszTOTP = get_totek_at(lpBase32SecretSeed, now, uiPeriod, SHA1, &err);
    if (lpszTOTP == NULL)
    {
        return CRYPT_TOTP_FAILED;
    }

    memcpy(ucPasswdBuf, lpszTOTP, 10);
    free(lpszTOTP);
    memcpy(ucPasswdBuf + 10, ucPasswd, 22);

    iKeysize = mcrypt_enc_get_key_size(td);
    //printf("iKeysize: %d\n", iKeysize);
    if (iKeysize < 32)
    {
        printf("error: iKeysize: %d\n", iKeysize);
        return CRYPT_KEYSIZE_INVALID;
    }

    iRes = mcrypt_generic_init(td, ucPasswdBuf, iKeysize, NULL);
    if (iRes < 0)
    {
        printf("error: mcrypt_generic_init iRes: %d\n", iRes);
        mcrypt_perror(iRes);
        return CRYPT_ENCRYPT_FAILED;
    }

    {
        char cLogBuf[8192] = {0};
        fprintf(fhLog, "\n======before encryption=======\n");
        fprintf(fhLog, "*lpuiBufLen: %d\n", *lpuiBufLen);
        for (int i = 0; i < *lpuiBufLen; i++)
        {
            sprintf(cLogBuf + i * 3, " %02X", lpucBuf[i]);
        }
        fwrite(cLogBuf, 1, strlen(cLogBuf), fhLog);
        fprintf(fhLog, "\n==============================\n");
    }

    iRes = mcrypt_generic(td, lpucBuf, iCnt);
    mcrypt_generic_deinit(td);

    if (iRes != 0)
    {
        printf("error: mcrypt_generic iRes: %d\n", iRes);
        return CRYPT_ENCRYPT_FAILED;
    }
    *lpuiBufLen = iCnt;

    {
        char cLogBuf[8192] = {0};
        fprintf(fhLog, "\n******after encryption********\n");
        fprintf(fhLog, "*lpuiBufLen: %d\n", *lpuiBufLen);
        for (int i = 0; i < *lpuiBufLen; i++)
        {
            sprintf(cLogBuf + i * 3, " %02X", lpucBuf[i]);
        }
        fwrite(cLogBuf, 1, strlen(cLogBuf), fhLog);
        fprintf(fhLog, "\n******************************\n");
    }
    /*
    for (int i = 0; i < *lpuiBufLen; i++)
    {
        printf(" %02X", lpucBuf[i]);
    }
    putchar('\n');
    */

    //printf("**********************************************************\n");
    return CRYPT_SUCCESS;
}

crypt_error_t tryDataDecryptionTOTP(MCRYPT td, unsigned char ucPasswd[22], unsigned char *lpucBuf, unsigned int *lpuiBufLen, time_t now, unsigned int uiTOTPCnt, unsigned int uiPeriod, char *lpBase32SecretSeed)
{
    char *lpKeyArray;
    cotp_error_t err;
    char *lpszTOTP;
    int iRes = 0;
    int iBlocksize = 0;
    int iKeysize = 0;
    int iCnt;
    unsigned int uiCRC32 = 0;
    PPacket lpPacket = (PPacket)lpucBuf;
    unsigned char ucTmpBuf[MAX_DATA_LEN + offsetof(Packet, ucBuf)];

    if (uiTOTPCnt % 2 == 0)
    {
        return CRYPT_INVALID_TOTP_COUNT;
    }

    iBlocksize = mcrypt_enc_get_block_size(td);
    //printf("iBlocksize: %d\n", iBlocksize);

    iCnt = ((*lpuiBufLen - 1) / iBlocksize + 1) * iBlocksize;  // pad to block size
    //printf("iCnt: %d\n", iCnt);
    //printf("sizeof(Packet): %lu\n", sizeof(Packet));
    if (iCnt > sizeof(Packet))
    {
        return CRYPT_BLK_NOTFIT;
    }

    iKeysize = mcrypt_enc_get_key_size(td);
    //printf("iKeysize: %d\n", iKeysize);
    if (iKeysize < 32)
    {
        printf("iKeysize: %d\n", iKeysize);
        return CRYPT_KEYSIZE_INVALID;
    }

    lpKeyArray = calloc(uiTOTPCnt, iKeysize);

    lpszTOTP = get_totek_at(lpBase32SecretSeed, now, uiPeriod, SHA1, &err);
    if (lpszTOTP == NULL)
    {
        free(lpKeyArray);
        return CRYPT_TOTP_FAILED;
    }

    memcpy(lpKeyArray, lpszTOTP, 10);
    free(lpszTOTP);
    memcpy(lpKeyArray + 10, ucPasswd, 22);

    /*
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    for (int i = 0; i < 32; i++)
    {
        printf(" %02X", (unsigned char)lpKeyArray[i]);
    }
    putchar('\n');
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    */

    for (int i = 0; i < uiTOTPCnt / 2; i++)
    {
        lpszTOTP = get_totek_at(lpBase32SecretSeed, now - uiPeriod * (i + 1), uiPeriod, SHA1, &err);
        if (lpszTOTP == NULL)
        {
            free(lpKeyArray);
            return CRYPT_TOTP_FAILED;
        }
        //printf("lpszTOTP: %s\n", lpszTOTP);
        memcpy(lpKeyArray + (iKeysize * (i * 2 + 1)), lpszTOTP, 10);
        free(lpszTOTP);
        memcpy(lpKeyArray + (iKeysize * (i * 2 + 1)) + 10, ucPasswd, 22);
        /*
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        for (int j = 0; j < 32; j++)
        {
            printf(" %02X", (unsigned char)(lpKeyArray + (iKeysize * (i * 2 + 1)))[j]);
        }
        putchar('\n');
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        */

        lpszTOTP = get_totek_at(lpBase32SecretSeed, now + uiPeriod * (i + 1), uiPeriod, SHA1, &err);
        if (lpszTOTP == NULL)
        {
            free(lpKeyArray);
            return CRYPT_TOTP_FAILED;
        }
        //printf("lpszTOTP: %s\n", lpszTOTP);
        memcpy(lpKeyArray + (iKeysize * (i * 2 + 2)), lpszTOTP, 10);
        free(lpszTOTP);
        memcpy(lpKeyArray + (iKeysize * (i * 2 + 2)) + 10, ucPasswd, 22);
        /*
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        for (int j = 0; j < 32; j++)
        {
            printf(" %02X", (unsigned char)(lpKeyArray + (iKeysize * (i * 2 + 2)))[j]);
        }
        putchar('\n');
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        */
    }

    memcpy(ucTmpBuf, lpucBuf, *lpuiBufLen);

    for (int i = 0; i < uiTOTPCnt; i++)
    {
        iRes = mcrypt_generic_init(td, lpKeyArray + (iKeysize * i), iKeysize, NULL);
        if (iRes < 0)
        {
            mcrypt_perror(iRes);
            printf("mcrypt_generic_init iRes: %d\n", iRes);
            return CRYPT_DECRYPT_FAILED;
        }

        memcpy(lpucBuf, ucTmpBuf, *lpuiBufLen);

        {
            char cLogBuf[8192] = {0};
            fprintf(fhLog, "\n******before decryption*******\n");
            fprintf(fhLog, "*lpuiBufLen: %d\n", *lpuiBufLen);
            for (int i = 0; i < *lpuiBufLen; i++)
            {
                sprintf(cLogBuf + i * 3, " %02X", lpucBuf[i]);
            }
            fwrite(cLogBuf, 1, strlen(cLogBuf), fhLog);
            fprintf(fhLog, "\n******************************\n");
        }

        iRes = mdecrypt_generic(td, lpucBuf, iCnt);
        mcrypt_generic_deinit(td);

        if (iRes != 0)
        {
            printf("error: mdecrypt_generic iRes: %d\n", iRes);
            free(lpKeyArray);
            return CRYPT_DECRYPT_FAILED;
        }
        *lpuiBufLen = iCnt;

        {
            char cLogBuf[8192] = {0};
            fprintf(fhLog, "\n======after decryption========\n");
            fprintf(fhLog, "*lpuiBufLen: %d\n", *lpuiBufLen);
            for (int i = 0; i < *lpuiBufLen; i++)
            {
                sprintf(cLogBuf + i * 3, " %02X", lpucBuf[i]);
            }
            fwrite(cLogBuf, 1, strlen(cLogBuf), fhLog);
            fprintf(fhLog, "\n==============================\n");
        }

        if (lpPacket->usLen > MAX_DATA_LEN)
        {
            fprintf(fhLog, "error: lpPacket->usLen: %d\n", lpPacket->usLen);
            printf("error: lpPacket->usLen: %d\n", lpPacket->usLen);
            continue;
        }

        gcry_md_hash_buffer(GCRY_MD_CRC32, &uiCRC32, lpPacket->ucBuf, lpPacket->usLen);
        /*
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        printf("lpPacket->usLen: %d\n", lpPacket->usLen);
        for (int i = 0; i < lpPacket->usLen; i++)
        {
            printf(" %02X", lpPacket->ucBuf[i]);
        }
        putchar('\n');
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        */
        if (lpPacket->uiCRC32 != uiCRC32)
        {
            printf("error: lpPacket->uiCRC32 != uiCRC32\n");
            fprintf(fhLog, "error: lpPacket->uiCRC32 != uiCRC32\n");
            printf("lpPacket->uiCRC32: %X\n", lpPacket->uiCRC32);
            fprintf(fhLog, "lpPacket->uiCRC32: %X\n", lpPacket->uiCRC32);
            printf("uiCRC32: %X\n", uiCRC32);
            fprintf(fhLog, "uiCRC32: %X\n", uiCRC32);
            printf("lpPacket->uiRand: %X\n", lpPacket->uiRand);
            fprintf(fhLog, "lpPacket->uiRand: %X\n", lpPacket->uiRand);
            continue;
        }

        free(lpKeyArray);
        return CRYPT_SUCCESS;
    }

    free(lpKeyArray);
    return CRYPT_DECRYPT_FAILED;
}

union sockaddr_4or6
{
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    struct sockaddr a;
};

int main(int argc, char **argv)
{
    struct addrinfo hints;
    //struct addrinfo *result, *rp;
    struct addrinfo *result;

    int dev, cnt, sock;
    unsigned int slen;
    unsigned char buf[1536];
    union sockaddr_4or6 addr, from;
#ifndef __NetBSD__
    struct ifreq ifr;
#endif

    MCRYPT td;
    //int i;
    unsigned char *key; 
    int blocksize = 0;
    int keysize = 32; /* 256 bits == 32 bytes */
    //char enc_state[1024];
    //int enc_state_size;
    char* tun_device = "/dev/net/tun";
    char* dev_name = "tun%d";
    int tuntap_flag = IFF_TAP;
    const char *K = "this is a secret";
    baseencode_error_t base_err;
    char *lpBase32Secret = base32_encode((unsigned char *)K, strlen(K) + 1, &base_err);
    fhLog = fopen("/root/totptunnel.log", "w");

    if (getenv("TUN_DEVICE"))
    {
        tun_device = getenv("TUN_DEVICE");
    }

    if (getenv("DEV_NAME"))
    {
        dev_name = getenv("DEV_NAME");
    }

    if (getenv("IFF_TUN"))
    {
        tuntap_flag = IFF_TUN;
    }

    if (getenv("MCRYPT_KEYFILE"))
    {
        if (getenv("MCRYPT_KEYSIZE"))
        {
            keysize = atoi(getenv("MCRYPT_KEYSIZE")) / 8;
        }
        key = calloc(1, keysize);
        FILE* keyf = fopen(getenv("MCRYPT_KEYFILE"), "r");
        if (!keyf)
        {
            perror("fopen keyfile");
            return 10;
        }
        memset(key, 0, keysize);
        fread(key, 1, keysize, keyf);
        fclose(keyf);

        char* algo = "twofish";
        char* mode = "cbc";

        if (getenv("MCRYPT_ALGO"))
        {
            algo = getenv("MCRYPT_ALGO");
        }

        if (getenv("MCRYPT_MODE"))
        {
            mode = getenv("MCRYPT_MODE");
        }

        td = mcrypt_module_open(algo, NULL, mode, NULL);
        if (td == MCRYPT_FAILED)
        {
            fprintf(stderr, "mcrypt_module_open failed algo=%s mode=%s keysize=%d\n", algo, mode, keysize);
            return 11;
        }
        blocksize = mcrypt_enc_get_block_size(td);
        printf("blocksize: %d\n", blocksize);
    }
    else
    {
        fprintf(stderr, "MCRYPT_KEYFILE is not set\n");
        exit(1);
    }

    if (argc < 3)
    {
        fprintf(stderr,
                "Usage: udptap [-6] <localip> <localport> [<remotehost> <remoteport>]\n"
                "    Environment variables:\n"
                "    TUN_DEVICE  /dev/net/tun\n"
                "    DEV_NAME    name of the device, default tun%%d\n"
                "    IFF_TUN     if set, uses point-to-point instead ot TAP.\n"
                "    \n"
                "    MCRYPT_KEYFILE  -- turn on encryption, read key from this file\n"
                "    MCRYPT_KEYSIZE  -- key size in bits, default 256\n"
                "    MCRYPT_ALGO     -- algorithm, default is twofish. aes256 is called rijndael-256\n"
                "    MCRYPT_MODE     -- mode, default is CBC\n"
                "    IPV6_V6ONLY     -- bind socket only to IPv6\n"
               );
        exit(1);
    }

    int ip_family;
    if (!strcmp(argv[1], "-6"))
    {
        ++argv;
        ip_family = AF_INET6;
        slen = sizeof(struct sockaddr_in6);
    }
    else
    {
        ip_family = AF_INET;
        slen = sizeof(struct sockaddr_in);
    }

    int autoaddress = 1;  // server mode is 1
    char* laddr = argv[1];
    char* lport = argv[2];
    char* rhost = NULL;
    char* rport = NULL;

    if (argc == 5)
    {
        // client mode is 0
        autoaddress = 0;
        rhost = argv[3];
        rport = argv[4];
    }

    if ((dev = open(tun_device, O_RDWR)) < 0)
    {
        fprintf(stderr, "open(%s) failed: %s\n", tun_device, strerror(errno));
        exit(2);
    }

#ifndef __NetBSD__
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tuntap_flag | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if (ioctl(dev, TUNSETIFF, (void*) &ifr) < 0)
    {
        perror("ioctl(TUNSETIFF) failed");
        exit(3);
    }
#endif

    if((sock = socket(ip_family, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket() failed");
        exit(4);
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_family = ip_family;

    if (getaddrinfo(laddr, lport, &hints, &result))
    {
        perror("getaddrinfo for local address");
        exit(5);
    }
    if (!result)
    {
        fprintf(stderr, "getaddrinfo for remote returned no addresses\n");
        exit(6);
    }
    if (result->ai_next)
    {
        fprintf(stderr, "getaddrinfo for local returned multiple addresses\n");
    }
    memcpy(&addr.a, result->ai_addr, result->ai_addrlen);

#ifdef IPV6_V6ONLY
    if (ip_family == AF_INET6)
    {
        int s = 0;
        if(getenv("IPV6_V6ONLY"))
            s = atoi(getenv("IPV6_V6ONLY"));
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &s, sizeof(int));
    }
#endif //IPV6_V6ONLY

    if (bind(sock, (struct sockaddr *)&addr.a, slen))
    {
        fprintf(stderr, "bind() to port %s failed: %s\n", lport, strerror(errno));
        exit(5);
    }

    memset(&addr.a, 0, result->ai_addrlen);
    freeaddrinfo(result);

    if (!autoaddress)
    {
        // client mode
        if (getaddrinfo(rhost, rport, &hints, &result))
        {
            perror("getaddrinfo for remote address");
            exit(5);
        }
        if (result->ai_next)
        {
            fprintf(stderr, "getaddrinfo for remote returned multiple addresses\n");
        }
        if (!result)
        {
            fprintf(stderr, "getaddrinfo for remote returned no addresses\n");
            exit(6);
        }
        memcpy(&addr.a, result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(dev, F_SETFL, O_NONBLOCK);
    int maxfd = (sock > dev) ? sock : dev;

    //mcrypt_generic_init(td, key, keysize, NULL);

    //enc_state_size = sizeof enc_state;
    //mcrypt_enc_get_state(td, enc_state, &enc_state_size);

    for(;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(dev, &rfds);
        int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);

        if (ret < 0)
            continue;

        if (FD_ISSET(dev, &rfds))
        {
            Packet stPacket;
            unsigned int uiCRC32 = 0;
            unsigned int uiBufLen;
            unsigned int uiRand;
            ssize_t siRet __attribute__((unused));
            siRet = getrandom(&uiRand, sizeof(unsigned int), GRND_NONBLOCK);
            time_t now;

            cnt = read(dev, (void*)&buf, MAX_DATA_LEN);
            if (blocksize)
            {
                //cnt = ((cnt - 1) / blocksize + 1) * blocksize; // pad to block size
                //mcrypt_generic(td, buf, cnt);

                gcry_md_hash_buffer(GCRY_MD_CRC32, &uiCRC32, buf, cnt);

                stPacket.uiRand = uiRand;
                stPacket.uiCRC32 = uiCRC32;
                stPacket.usLen = cnt;
                memcpy(stPacket.ucBuf, buf, cnt);
                uiBufLen = cnt + offsetof(Packet, ucBuf);
                now = time(NULL);

                crypt_error_t iRetEncrypt __attribute__((unused)) = encryptDataTOTP(td, key + 10, (unsigned char *)&stPacket, &uiBufLen, now, 30, lpBase32Secret);
                if (iRetEncrypt != CRYPT_SUCCESS)
                {
                    printf("encryptDataTOTP iRetEncrypt: %d\n", iRetEncrypt);
                    printf("encryptDataTOTP return uiBufLen: %d\n", uiBufLen);
                }
            }
            sendto(sock, &stPacket, uiBufLen, 0, &addr.a, slen);
        }

        if (FD_ISSET(sock, &rfds))
        {
            unsigned int uiBufLen;
            time_t now;

            cnt = recvfrom(sock, &buf, MAX_DATA_LEN + offsetof(Packet, ucBuf), 0, &from.a, &slen);

            int address_ok = 0;

            if (!autoaddress)
            {
                // client mode
                if (ip_family == AF_INET)
                {
                    //printf("ip_family: %d\n", ip_family);
                    if ((from.a4.sin_addr.s_addr == addr.a4.sin_addr.s_addr) && (from.a4.sin_port == addr.a4.sin_port))
                    {
                        address_ok = 1;
                    }
                } else {
                    //printf("ip_family: %d\n", ip_family);
                    if ((!memcmp(
                                    from.a6.sin6_addr.s6_addr,
                                    addr.a6.sin6_addr.s6_addr,
                                    sizeof(addr.a6.sin6_addr.s6_addr))
                        ) && (from.a6.sin6_port == addr.a6.sin6_port))
                    {
                        address_ok = 1;
                    }
                }
            }
            else
            {
                // server mode
                memcpy(&addr.a, &from.a, slen);
                address_ok = 1;
            }

            if (address_ok)
            {
                if (blocksize)
                {
                    //cnt = ((cnt - 1) / blocksize + 1) * blocksize; // pad to block size
                    //mdecrypt_generic(td, buf, cnt);
                    //mcrypt_enc_set_state(td, enc_state, enc_state_size);
                    now = time(NULL);
                    uiBufLen = cnt;
                    crypt_error_t iRetDecrypt __attribute__((unused)) = tryDataDecryptionTOTP(td, key + 10, (unsigned char *)&buf, &uiBufLen, now, 5, 30, lpBase32Secret);
                    if (iRetDecrypt != CRYPT_SUCCESS)
                    {
                        printf("tryDataDecryptionTOTP iRetDecrypt: %d\n", iRetDecrypt);
                        printf("tryDataDecryptionTOTP cnt: %d\n", cnt);
                        printf("tryDataDecryptionTOTP return uiBufLen: %d\n", uiBufLen);
                        PPacket lpPacket = (PPacket)buf;
                        printf("lpPacket->usLen: %d\n", lpPacket->usLen);
                    }
                }
                PPacket lpPacket = (PPacket)buf;
                ssize_t iWriteRet = write(dev, &lpPacket->ucBuf, lpPacket->usLen);
                //printf("&lpPacket->ucBuf - &lpPacket->usLen: %ld\n", (void *)&lpPacket->ucBuf - (void *)&lpPacket->usLen);
                //printf("&lpPacket->ucBuf - &lpPacket->uiRand: %ld\n", (void *)&lpPacket->ucBuf - (void *)&lpPacket->uiRand);
                if (iWriteRet == -1)
                {
                    printf("iWriteRet: %ld\n", iWriteRet);
                    printf("errno: %s\n", strerror(errno));
                }
            }
        }
    }

    free(lpBase32Secret);
    fclose(fhLog);
    if (blocksize)
    {
        mcrypt_generic_deinit(td);
        mcrypt_module_close(td);
    }
}
