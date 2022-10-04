all: \
	udptap_tunnel

udptap_tunnel: udptap.c
		${CC} ${CFLAGS}  -Wall udptap.c -lmcrypt -lcotp -lgcrypt ${LDFLAGS} -o udptap_tunnel
