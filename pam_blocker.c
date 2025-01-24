#include<sys/param.h>
#include<pwd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<security/pam_modules.h>
#include<security/pam_appl.h>
#include<security/pam_ext.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<syslog.h>
#include<errno.h>

#define Max_Attempt 2
#define Max_count 100
#define LOG_FILE "/var/log/blocked_ips.log"


typedef struct {
        char ip[INET_ADDRSTRLEN];
        int attempts;
} IPAttempt;

static IPAttempt ip_attempt[Max_count];
static int ip_count = 0;

void log_blocked_ip(const char *ip){
        FILE *log_file = fopen( LOG_FILE, "a");
        if(log_file == NULL){
                syslog(LOG_ERR, "failed to open log file: %s", strerror(errno));
                return;
        }
        fprintf(log_file, "Blocked IP: %s\n", ip);
        fclose(log_file);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv){
       const char *user;
       const void *rhost;
       int pam_err;
       int i;

       if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS){
         return pam_err;
       }

      pam_err = pam_get_item(pamh, PAM_RHOST, &rhost);
      if (pam_err != PAM_SUCCESS || rhost == NULL){
          pam_syslog(pamh, LOG_ERR, "Failed to get remote host IP");
          return PAM_AUTH_ERR;
      }

      for (i = 0; i < ip_count; i++){
          if (strcmp(ip_attempt[i].ip, (char *)rhost) == 0 && ip_attempt[i].attempts >= Max_Attempt){
          pam_syslog(pamh, LOG_NOTICE,"%s is blocked", (char *)rhost);
          log_blocked_ip((char *)rhost);

          pam_prompt(pamh, PAM_ERROR_MSG, NULL, "This IP address [%s] has been blocked", (char *)rhost);

          return PAM_AUTH_ERR;
          }
      }

      for (i = 0; i < ip_count; i++){
          if (strcmp(ip_attempt[i].ip, (char *)rhost) == 0) {
              ip_attempt[i].attempts++;
              pam_syslog(pamh,  LOG_NOTICE, "Failed attempt %d for IP %s", ip_attempt[i].attempts, (char *)rhost);
              if(ip_attempt[i].attempts >= Max_Attempt){
                      pam_syslog(pamh, LOG_NOTICE, "IP %s has been blocked", (char *)rhost);
                      log_blocked_ip((char *)rhost);

                      pam_prompt(pamh, PAM_ERROR_MSG, NULL, "This IP address [%s] has been blocked", (char *)rhost);

                      return PAM_AUTH_ERR;

              }
          return PAM_AUTH_ERR;
          }
       }

      if(ip_count >= Max_count){
              pam_syslog(pamh, LOG_ERR, "IP attempt storage is full, cannot track further IPs");
              return PAM_AUTH_ERR;
      }
      strncpy(ip_attempt[ip_count].ip, (char *)rhost, INET_ADDRSTRLEN - 1);
      ip_attempt[ip_count].ip[INET_ADDRSTRLEN - 1] = '\0';
      ip_attempt[ip_count].attempts = 1;
      ip_count++;
      pam_syslog(pamh, LOG_NOTICE, "Attempt to IP %s faild", (char *)rhost);
      return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv){
  return PAM_SUCCESS;
}
