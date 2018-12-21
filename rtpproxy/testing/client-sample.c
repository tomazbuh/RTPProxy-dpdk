/*
    C ECHO client example using sockets
*/
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include <unistd.h>
 
int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char message[1000] , server_reply[2000],temp[1000];
    int a;
     
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
    if (strcmp ("add",argv[1]) == 0) 
    {
	    //keep communicating with server
	    for (a =0 ;a<200;a++)
	    {
	        printf("Enter message : ");
	        //scanf("%s" , message);
		in_addr_t fsip,fdip,tsip,tdip;
		int fsport,fdport,tsport,tdport;
		sprintf(temp,"172.1.1.%d",a);
		fsip=inet_addr(temp);
		fsport=htons(1200);
		fdip=inet_addr("172.1.1.2");
		fdport=htons(13000);
		tsip=inet_addr("173.1.1.1");
		tsport=htons(1230);
		tdip=inet_addr("173.1.1.2");
		tdport=htons(1234);
	
	        //sprintf(message,"172.1.1.%d 172.1.1.2 1200 13000 173.1.1.1 173.1.1.2 1230 1234 %d\n",a,IPPROTO_UDP);
	        sprintf(message,"1 %u %u %u %u %u %u %u %u\n",fsip,fsport,fdip,fdport,tsip,tsport,tdip,tdport);
         
	        //Send some data
	        if( send(sock , message , strlen(message) , 0) < 0)
	        {
	            puts("Send failed");
	            return 1;
	        }
         
	        //Receive a reply from the server
	        if( recv(sock , server_reply , 2000 , 0) < 0)
	        {
	            puts("recv failed");
        	    break;
	        }
         
	        puts("Server reply :");
	        puts(server_reply);
    	}
    }
    else if (strcmp ("rem",argv[1]) == 0) 
    {
	    //keep communicating with server
	    for (a =0 ;a<200;a++)
	    {
	        printf("Enter message : ");
	        //scanf("%s" , message);
		in_addr_t fsip,fdip,tsip,tdip;
		int fsport,fdport,tsport,tdport;
		sprintf(temp,"172.1.1.%d",a);
		fsip=inet_addr(temp);
		fsport=htons(1200);
		fdip=inet_addr("172.1.1.2");
		fdport=htons(13000);
		tsip=inet_addr("173.1.1.1");
		tsport=htons(1230);
		tdip=inet_addr("173.1.1.2");
		tdport=htons(1234);
	
	        //sprintf(message,"172.1.1.%d 172.1.1.2 1200 13000 173.1.1.1 173.1.1.2 1230 1234 %d\n",a,IPPROTO_UDP);
	        sprintf(message,"0 %u %u %u %u %u %u %u %u\n",fsip,fsport,fdip,fdport,tsip,tsport,tdip,tdport);
         
	        //Send some data
	        if( send(sock , message , strlen(message) , 0) < 0)
	        {
	            puts("Send failed");
	            return 1;
	        }
         
	        //Receive a reply from the server
	        if( recv(sock , server_reply , 2000 , 0) < 0)
	        {
	            puts("recv failed");
        	    break;
	        }
         
	        puts("Server reply :");
	        puts(server_reply);
    	}
    }
    else  
    {
	printf("command missing\n");	

    }
     
    close(sock);
    return 0;
}
