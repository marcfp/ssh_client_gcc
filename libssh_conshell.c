#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
 


#include <errno.h>
#include <string.h>

#define Deb 1

/*show_remote_files*/
int show_remote_files(ssh_session session)
{
  ssh_channel channel;
  int rc;
 
 printf("\nlinea 16 show_remote_files\n");
 //sleep(50000);
  channel = ssh_channel_new(session);
  if (channel == NULL){ 
                printf("channel és NULL!!!");
                return SSH_ERROR;
  }
 
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    printf("\nlinea27 \nrc != SSH_OK!!!!\n");
    ssh_channel_free(channel);
    return rc;
  }
  rc = ssh_channel_request_exec(channel, "ls -l");
  if (rc != SSH_OK)
  {
    printf("\nlinea34 \nrc != SSH_OK!!!!\n");
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
  char buffer[256];
  int nbytes;
 
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
  
  if (nbytes < 0)
  {
    printf("\nlinea56 \n nbytes < 0!!!!\n");
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
 printf("\nlinea 64 show_remote_files\n");
  return SSH_OK;
}


int kbhit()
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;
 
    FD_ZERO(&fds);
    FD_SET(0, &fds);
 
    return select(1, &fds, NULL, NULL, &tv);
}

int interactive_shell_session(ssh_channel channel)
{
  int rc;
  char buffer[256];
  int nbytes;   

  printf("\n\n\ndins de interactive_shell_session\n\n\n");
  rc = ssh_channel_request_pty(channel);
  //if (rc != SSH_OK) return rc;
 printf("\n\n\interactive_shell_session linea 89\n\n\n");
  rc = ssh_channel_change_pty_size(channel, 80, 24);
  //if (rc != SSH_OK) return rc;
 printf("\n\n\interactive_shell_session linea 92\n\n\n");
  rc = ssh_channel_request_shell(channel);
  //if (rc != SSH_OK) return rc;
 printf("\n\n\interactive_shell_session linea 95\n\n\n");
  /*while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel))
  {
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes < 0)
      return SSH_ERROR;
 
    if (nbytes > 0)
      write(1, buffer, nbytes);
  }*/
  int nwritten;
 
  while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel))
  {
    nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);  
    if (nbytes < 0){ printf("nbytes <0 linea 109\n"); return SSH_ERROR;}
    if (nbytes > 0)
    {
      nwritten = write(1, buffer, nbytes);
      if (nwritten != nbytes) return SSH_ERROR;
    }
    if (!kbhit())
    {
      usleep(50000L); // 0.05 second
      continue;
    }
 
    nbytes = read(0, buffer, sizeof(buffer));
    if (nbytes < 0) { printf("nbytes <0 linea 122\n"); return SSH_ERROR;}
    if (nbytes > 0)
    {
      nwritten = ssh_channel_write(channel, buffer, nbytes);
      if (nwritten != nbytes) return SSH_ERROR;
      //mostrar prompt ? com ? 
      //https://api.libssh.org/stable/libssh_tutor_shell.html
      //printf("\nbuffer = %s",&buffer);
      //printf("\nnwritten = %s",&nwritten);
      ////show_remote_files(channel);//session);
    }
  }
  return rc;
}


/* Remote shell*/
//https://api.libssh.org/stable/libssh_tutor_shell.html
//https://api.libssh.org/stable/libssh_tutor_shell.html
int shell_session(ssh_session session)
{
  ssh_channel channel;
  int rc;
 
  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
 
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
 
//  ...
  printf("\n\n\n\n Shell_session oberta!\n\n\n\n\n");
 
 // interactive_shell_session(channel);
  //show_remote_files(session);
  //printf("shell_session linea 155 : %s",ssh_channel_request_shell(channel));
  //interactive_shell_session(channel);
  ssh_channel_request_shell(channel);
  ssh_channel_request_pty(channel);
  ssh_channel_request_pty_size( channel, "Terminal prova", 80, 60);		printf("\nentro dins de iteractive_shell_session\n");
  //show_remote_files(session);
  interactive_shell_session(channel);
  ssh_channel_close(channel);
  ssh_channel_send_eof(channel);
  ssh_channel_free(channel);
 
  return SSH_OK;
}

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
            fprintf(stderr,"Know host!!!! estic dins i bé, segons sembla");
            printf("\nVersió ssh : %d \n",ssh_get_openssh_version(session));

            shell_session(session);
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int display_banner(ssh_session session)
{
  int rc;
  char *banner;
 
/*
   * Does not work without calling ssh_userauth_none() first ***
   * That will be fixed ***
*/
  rc = ssh_userauth_none(session, NULL);
  if (rc == SSH_AUTH_ERROR)
    return rc;
 
  banner = ssh_get_issue_banner(session);
  if (banner)
  {
    printf("%s\n", banner);
    free(banner);
  }
 
  return rc;
}



int main(int argc, char *argv[])
{
  ssh_session my_ssh_session;
  int rc;
  char *password='\0';
  char pass[256];
   for (int i = 0; i < argc; ++i)
    {
      if(Deb) printf("argv[%d]: %s\n", i, argv[i]);
    }
 
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
 //printf("\nargc = %d\n",argc);

 my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
 

 if(argc == 3){
      char ip[strlen(argv[1])];
      if (argv[1]){ // ip
        if(Deb) printf(" ip = %s\nallargada = %d\n",argv[1],strlen(argv[1]));
        if(Deb) printf(" \nip(string) = %s\n",strcpy(ip,argv[1]));
      }
      char nom_user[strlen(argv[2])];
      if (argv[2]){ // nom user
        if(Deb) printf(" ip = %s\nallargada = %d\n",argv[2],strlen(argv[2]));
        if(Deb) printf(" \nnom user(string) = %s\n",strcpy(nom_user,argv[2]));  
      }
      
      
      ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip);//"localhost");
      ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, nom_user);
 }
 else{
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.1.139");//"localhost");
      ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "Marc");
 }
 //inicialitzo bé les variables ? revisar-ho
if(Deb)printf("\n\n\n\n\n\n\n\n comprobar si INICIALITZO BÉ LES variables!!!! i debugar, pk obra 2 canals \n\n\n\n\n\n\n\n");
 //ssh_options_get(my_ssh_session, SSH_OPTIONS_USER);
 //printf("%s",&my_ssh_session['SSH_OPTIONS_USER']);
 
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
    exit(-1);
  }
   // Verify the server's identity
  // For the source code of verify_knownhost(), check previous example
  if (verify_knownhost(my_ssh_session) < 0)
  {
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }

    // Authenticate ourselves
  if( ssh_getpass("Password: ",pass,sizeof(pass),0,1)){
    fprintf(stderr, "Password ok\n");
  }
  /*else{
    fprintf(stderr, "Password KO!\n");
    printf("\n password entrat = %s",&pass);
    exit(-1);
  }*/
  rc = ssh_userauth_password(my_ssh_session, "marc" /*SSH_OPTIONS_USER*/, pass);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
  else{
    fprintf(stderr, "\n\n\n verificat correctament!!!\n\n\n");
    //display_banner(my_ssh_session);
    verify_knownhost(my_ssh_session);

  }

//  ...
 
  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}
