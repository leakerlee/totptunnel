all: \
	udptap

udptap: udptap.c
		#${CC} ${CFLAGS} -Wall udptap.c -lmcrypt -lcotp -lgcrypt ${LDFLAGS} -o udptap
		${CC} ${CFLAGS} -Wall udptap.c /usr/lib/x86_64-linux-gnu/libmcrypt.a /usr/lib/x86_64-linux-gnu/libgcrypt.a /usr/lib/x86_64-linux-gnu/libgpg-error.a /home/bayern/proj.d/libcotp/build/libcotp.static.a -lbaseencode ${LDFLAGS} -o udptap

