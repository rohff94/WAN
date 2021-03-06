#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
 
int main(int argc, char**argv) { 
	char* cmd1;
        char* cmd2 ;
	char query1[200048];
	char query2[200048];
	char command1[200048];
	char command2[200048];

	char* time2sleep;
        int laps ;

if (argc != 4) {
	printf("\t\t\033[37;41;1;1m Usage: %s cmd1 cmd2 time2sleep \033[0m\n",argv [0]);
	exit ( 0 );
}


  
  cmd1 = argv[1] ;
  cmd2 = argv[2] ;
  time2sleep = argv[3] ;
  laps = atoi(time2sleep);
 
  //printf("cmd1:%s cmd2:%s time2sleep:%s laps:%d\n ", cmd1,cmd2,time2sleep,laps);


  sprintf(query1,"echo '%s' | base64 -d | bash ",cmd1);
  sprintf(query2,"echo '%s' | base64 -d | bash ",cmd2);

  sprintf(command1,"xterm -T 'CMD1' -e '%s' 2> /dev/null",query1);
  sprintf(command2,"xterm -T 'CMD2' -e '%s' 2> /dev/null",query2);
  

  pid_t ret_val = fork(); 
  if(ret_val == 0) { 
    printf("Child process. PID=%d, PPID=%d\n", getpid(), getppid());
    printf("\t\033[36;40;1;1m 1: \033[0m \033[33;40;1;1m %s \033[0m\n", query1);
    system(query1);
    //system(command1);

  } else if (ret_val>0) { 
    sleep(laps);
    printf("Parent process. PID=%d, PPID=%d\n", getpid(), getppid());
    printf("\t\033[36;40;1;1m 2: \033[0m \033[33;40;1;1m %s \033[0m\n", query2);
    system(query2);
    //system(command2);

	int status ;
        while ((ret_val = waitpid(ret_val, &status, 0)) == -1) {
            switch (errno) {
                case EINTR:
                    printf("waitpid failed with EINTR. Retrying...");
                    continue;
                default:
                    printf("waitpid failed");
                    break;
            }
        }

        printf("\t\033[37;45;1;7m Child exited with %d \033[0m\n", WEXITSTATUS(status));




  } else { 
    printf("Fork failed\n"); 
  } 
  return EXIT_SUCCESS; 

}
