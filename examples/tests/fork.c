#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#define MAX_CHILDREN 1024

int main(int argc, char *argv[])
{
   // First arg is the number copies
   static unsigned int start_time = 0;
   struct timeval tv = {0};
   pid_t children[MAX_CHILDREN] = {0};
   pid_t pid;
   int i, num_children = argc > 1 ? strtod(argv[1], NULL) : 0;
   if (argc < 3) {
      return -1;
   }
   gettimeofday(&tv, NULL);
   start_time = tv.tv_sec + 10;
   for (i = 0; i < num_children; i++) {
      children[i] = fork();
      if (children[i] < 0) {
         perror("Fork");
         exit(-1);
      } else if (children[i] == 0) {
#if 0
         pid = fork();
         if (pid < 0) {
            perror("Fork");
            exit(-1);
         } else if (pid > 0) {
            exit(0);
         }
#endif
         break;
      }
   }
   if (i == num_children) {
      for (i = 0; i < num_children; i++) {
         waitpid(children[i], NULL, 0);
      }
   } else {
      struct timeval t = {0};
      gettimeofday(&t, NULL);
      if (t.tv_sec < start_time)
         usleep(1000000 * (start_time - t.tv_sec) - t.tv_usec);
      execv(argv[2], argv + 2);
   }

   return 0;
}
