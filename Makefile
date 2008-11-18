MNAME=pam_kill

$(MNAME).so: $(MNAME).o
	ld -x -shared -o $(MNAME).so $(MNAME).o

pam_setquota.o: pam_setquota.c
	gcc -fPIC -DLINUX_PAM -Dlinux -Di386 -DPAM_DYNAMIC -c $(MNAME).c

install: $(MNAME).so
	install --mode=744 $(MNAME).so /lib/security

clean:
	rm -f $(MNAME).o $(MNAME).so

