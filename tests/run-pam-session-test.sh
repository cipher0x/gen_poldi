#!/bin/sh 

#Sets up libpam-wrapper preloader for libpam
#and starts session-test 

#bins
pam_session_test_id='/usr/bin/id'
pam_session_test_ls='/usr/bin/ls'

session_bin='session-test'

#set debug level
# 0 = Error
# 1 = Warning
# 2 = Debug
# 3 = Trace
pam_session_debuglevel=1

#preloader command with options
preloader_cmd="LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_USE_SYSLOG=0 PAM_WRAPPER_DEBUGLEVEL=${pam_session_debuglevel} PAM_WRAPPER_SERVICE_DIR=./services ./${session_bin}"

#paths
pam_session_run_dir='/run/user/'
pam_session_gpg_sock='/gnupg/S.gpg-agent'
pam_session_scd_sock='/gnupg/S.scdaemon'

pam_check_depd() {
   
   #check for id command
   if [ ! -f "${pam_session_test_id}" ]
   then
      printf 'Error id command required\n'
      return 1
   fi
   
   #check for ls command
   if [ ! -f "${pam_session_test_ls}" ]
   then
      printf 'Error ls command required\n'
      return 1
   fi
   
   return 0
   
}
pam_session_test_main () {

#check for dependices
if ! pam_check_depd
then
   return 1
fi

#check if gpg-agent/scd is running for user
if [ -f "${pam_session_test_id}" ]
then
   if [ ! -z "$1" ]
   then
      pam_session_uid=$(eval "${pam_session_test_id} --user $1")

      if eval "${pam_session_test_ls} ${pam_session_run_dir}${pam_session_uid}${pam_session_gpg_sock}" 2> '/dev/null'
      then
         printf 'Warning Found Running gpg-agent for user\n'
         printf 'Please stop gpg-agent before testing\n\n'
      fi
      
      if eval "${pam_session_test_ls} ${pam_session_run_dir}${pam_session_uid}${pam_session_scd_sock}" 2> '/dev/null'
      then
         printf 'Warning Found Running scdaemon for user\n'
         printf 'Please stop scdaemon before testing\n\n'
      fi
      
   fi
fi

#run session-test with preloader for libpam
if  [ -f "${session_bin}" ]
then
   printf '\nStarting libpam with preloader . . .\n\n'
   eval "${preloader_cmd} $1"
else
   printf 'Error Please compile session-test\n'
fi

   return 0
}

pam_session_test_main "$@"
