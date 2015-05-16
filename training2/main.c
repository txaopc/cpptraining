#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <curl/curl.h>

#define SKIP_PEER_VERIFICATION

int httpPost();
int multiPost();

void splitFile(char* filename, long int p_size);

int main(void)
{
    //splitFile("C:\\Users\\thaopc\\Desktop\\intimacy\\IntimacyVocab.mp3", 1024*1024);
    //httpPost();
    multiPost();
    return 0;
}

int multiPost(){

  CURL *curl;

  CURLM *multi_handle;
  int still_running;

  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char buf[] = "Expect:";

  /* Fill in the file upload field. This makes libcurl load data from
     the given file name when curl_easy_perform() is called. */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "file",
               CURLFORM_FILE, "D:\\thaopc\\softwares\\appserv-win32-2.5.10.exe",
               CURLFORM_END);

  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "name",
               CURLFORM_COPYCONTENTS, "appserv-win32-2.5.10.exe",
               CURLFORM_END);

  curl = curl_easy_init();
  multi_handle = curl_multi_init();

  /* initalize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl && multi_handle) {

#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, "https://txaopc.0fees.us/upload.php");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    curl_multi_add_handle(multi_handle, curl);

    curl_multi_perform(multi_handle, &still_running);

    do {
      struct timeval timeout;
      int rc; /* select() return code */
      CURLMcode mc; /* curl_multi_fdset() return code */

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd = -1;

      long curl_timeo = -1;

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);

      /* set a suitable timeout to play around with */
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      curl_multi_timeout(multi_handle, &curl_timeo);
      if(curl_timeo >= 0) {
        timeout.tv_sec = curl_timeo / 1000;
        if(timeout.tv_sec > 1)
          timeout.tv_sec = 1;
        else
          timeout.tv_usec = (curl_timeo % 1000) * 1000;
      }

      /* get file descriptors from the transfers */
      mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

      if(mc != CURLM_OK)
      {
        fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
        break;
      }

      /* On success the value of maxfd is guaranteed to be >= -1. We call
         select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
         no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
         to sleep 100ms, which is the minimum suggested value in the
         curl_multi_fdset() doc. */

      if(maxfd == -1) {
#ifdef _WIN32
        Sleep(100);
        rc = 0;
#else
        /* Portable sleep for platforms other than Windows. */
        struct timeval wait = { 0, 100 * 1000 }; /* 100ms */
        rc = select(0, NULL, NULL, NULL, &wait);
#endif
      }
      else {
        /* Note that on some platforms 'timeout' may be modified by select().
           If you need access to the original value save a copy beforehand. */
        rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
      }

      switch(rc) {
      case -1:
        /* select error */
        break;
      case 0:
      default:
        /* timeout or readable/writable sockets */
        printf("perform!\n");
        curl_multi_perform(multi_handle, &still_running);
        printf("running: %d!\n", still_running);
        break;
      }
    } while(still_running);

    curl_multi_cleanup(multi_handle);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);

    /* free slist */
    curl_slist_free_all (headerlist);
  }
  return 0;
}

int httpPost(){
    CURL *curl;
    CURLcode res;

    struct curl_httppost *formpost=NULL;
    struct curl_httppost *lastptr=NULL;
    struct curl_slist *headerlist=NULL;
    static const char buf[] = "Expect:";

    curl_global_init(CURL_GLOBAL_ALL);
    //"C:\\Users\\thaopc\\Desktop\\intimacy\\IntimacyAudio.mp3"
    /* Fill in the file upload field */
    curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "file",
               CURLFORM_FILE, "D:\\thaopc\\softwares\\appserv-win32-2.5.10.zip.002",
               CURLFORM_END);

    /* Fill in the filename field */
    curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "name",
               CURLFORM_COPYCONTENTS, "appserv-win32-2.5.10.zip",
               CURLFORM_END);
    curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "chunk",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);
    curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "chunks",
               CURLFORM_COPYCONTENTS, "2",
               CURLFORM_END);


    /* Fill in the submit field too, even if this is rarely needed */
    /*curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "submit",
               CURLFORM_COPYCONTENTS, "send",
               CURLFORM_END);*/

    curl = curl_easy_init();
    /* initalize custom header list (stating that Expect: 100-continue is not
     wanted */
    headerlist = curl_slist_append(headerlist, buf);
    if(curl) {
#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH,CURLAUTH_ANY);
    //curl_setopt(curl, CURLOPT_STDERR,  fopen("php://output", "w"));
    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, "https://txaopc.0fees.us/upload.php");
    //if ( (argc == 2) && (!strcmp(argv[1], "noexpectheader")) )
      /* only disable 100-continue header if explicitly requested */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);
    /* free slist */
    curl_slist_free_all (headerlist);
    }
    return 0;
}

void splitFile(char* filename, long int p_size){
    char nfn[250];
    int ch;
    long int size, n, k;
    int i;
    FILE *f, *ft; //file and temp file

    //printf("enter the file you want to split with full path : ");
    //scanf("%s", fn);
    //printf("enter the number of parts you want to split the file : ");
    //scanf("%ld", &n);

    f=fopen(filename, "rb");
    if (f==NULL)
    {
        printf("couldn't open file");
        exit(0);
    }

    fseek(f, 0, 2);
    size = ftell(f);
    printf("the size of the file in bytes is : %ld\n", size);

    i = 1;
    n = (int)ceil(size/(double)p_size);
    k = size/n;
    rewind(f);
    sprintf(nfn, "%s.%d", filename, i);
    ft = fopen(nfn, "wb");
    while(1)
    {
        ch = fgetc(f);
        if (ch==EOF)
            break;
        fputc(ch, ft);
        if (ftell(f)==(i*k))
        {
            i = i+1;
            fclose(ft);
            sprintf(nfn, "%s.%d", filename, i);
            ft=fopen(nfn, "wb");
        }
    }
}
