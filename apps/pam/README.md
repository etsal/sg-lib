# PAM Module

```pam_start``` creates a new PAM context and initiated the PAM transaction.

## PAM Service Modules

```auth``` - authentication
  * pam_authenticate
  * pam_setcred
```account``` - account management
  * pam_acc_mgmt
```session``` - session management
  * pam_open_session
```password``` - password management
  * ??

# Layout
  * ```pam-module/``` contains the PAM module code that is loaded by ```pam_start``` (check this).
  * ```pam-app/``` contains example applications that rely on the pam module.

# Background
1.  PAM shared object files are found under ```/usr/lib``` in FreeBSD. We install ```pam_example.so``` in ```/usr/lib```.

2. ```pam_example.config``` must be installed under ```/etc/pam.d/pam_example``` before running the PAM application (```pam-app```).

3. We rely on the ```../../server/``` to process our requests.

# Build & Install PAM Module
Run the following: ```cd build && cmake .. && gmake```, this will also do the installation. 

# Configure service with PAM
1. Create a PAM configuration file under ```/etc/pam.d/<service_name>```, with the following entries:

        auth        required    pam_sg.so
        account     required    pam_sg.so
        password    required    pam_unix.so

2. Make sure the ```pam_sg.so``` is installed in ```/usr/bin```. 

## Build & Run PAM Test Apps
