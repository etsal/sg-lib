1.  PAM shared object files are found under /usr/lib in freebsd. We install pam_example.so in /usr/lib

2. pam_example.config must be installed under /etc/pam.d/pam_example before running ./run_pam.o

3. server/ contains the code for the sgdaemon for talking to our db
