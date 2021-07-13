1.  PAM shared object files are found under /usr/lib in freebsd. We install pam_example.so in /usr/lib

2. pam_example.config must be installed under /etc/pam.d/pam_example before running ./run_pam.o

3. server/ contains the code for the sgdaemon for talking to our db



Workflow:
1. Run sudo ./server/build/app to run the sg daemon
2. Run sudo ./client/build/ipc_client to add users to the database (i.e. add stef password1234)
3. Run sudo ./pam-app/build/pam_app and fill in username and password as desired
