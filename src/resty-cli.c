
/*
 * Copyright (C) Jinhua Tan
 * A simple resty client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <stdint.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define FIFO_NAME "/tmp/nginx_fifo"
#define BUFFER_SIZE 4096
#define VERSION 0.1

#define RESTY_CLI_FILE         0x00000001
#define RESTY_CLI_CODE         0x00000002

#define  RESTY_CLI_OK          0
#define  RESTY_CLI_ERROR      -1

typedef struct {
    intptr_t    len;
    uintptr_t   type;
} resty_client_header;

typedef struct {
    int          port;
    char        *host;
    char        *code;
    int          type;
    int          fd;
} resty_client_context;


#define HEADER_SIZE sizeof(resty_client_header)

void usage()
{
    printf("resty-client version: %f\n", VERSION);
    printf("Usage: resty-cli [-?h] [-e code] [-f filename]\n");
    printf("Options:\n");
    printf("  -?,-h         : this help\n");
    printf("  -e code       : execute the CODE and return the result\n");
    printf("  -f filename   : execute the file's content and return the result\n");
    exit(EXIT_SUCCESS);
}

void get_args(int argc, char *argv[], resty_client_context *ctx)
{
    char   *p;
    FILE   *fp;
    int     len;

    p = (char *) argv[1];
    if (argc > 3) {
        usage();
    } else if ('-' == p[0]) {
        if (p[1] == 'h' || p[1] == '?') {
            usage(); 
        } else if (p[1] == 'e') {
            ctx->type = RESTY_CLI_CODE;
        } else if (p[1] == 'f') {
            ctx->type = RESTY_CLI_FILE;
        } else {
            usage(); 
        }
    } else {
        usage();
    }
    
    if (ctx->type == RESTY_CLI_CODE) {
        ctx->code = argv[2];
    } else if (ctx->type == RESTY_CLI_FILE) {
        fp = fopen((char *)argv[2], "r");
        if (! fp) {
            printf("Can't open the file: %s, %s.\n", argv[2], strerror(errno));
            exit(EXIT_FAILURE);
        }
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        ctx->code = malloc(len + 1);
        rewind(fp);
        fread(ctx->code, 1, len, fp);
        ctx->code[len] = '\0';
        fclose(fp);
    }
}

int connection(resty_client_context *ctx)
{
    struct sockaddr_in servaddr;

    ctx->fd = socket(AF_INET,SOCK_STREAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8220);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(ctx->fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("Connection error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    return RESTY_CLI_OK;
}

int sender(resty_client_context *ctx)
{
    resty_client_header   h;
    char                  buffer[BUFFER_SIZE];
    char                 *p;

    h.type = ctx->type;
    h.len = strlen(ctx->code);
    if(h.len > BUFFER_SIZE - HEADER_SIZE) {
        printf("Code is too long, please less then %d.\n", BUFFER_SIZE - HEADER_SIZE);
        exit(EXIT_FAILURE);
    }

    memset(buffer, '\0', BUFFER_SIZE);
    p = buffer + HEADER_SIZE;
    memmove(buffer, &h, HEADER_SIZE);
    memmove(p, ctx->code, h.len);
    
    //printf("Send code: %s\n", p);
    if (send(ctx->fd, buffer, h.len + HEADER_SIZE, 0) == -1) {
        printf("Send error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return RESTY_CLI_OK;
}

int receiver(resty_client_context *ctx)
{
    enum {
        R_BEGIN,
        R_HEADER,
        R_BODY,
        R_FINISH,
    } status;

    time_t                begin_t, execute_t;
    char                  buffer[BUFFER_SIZE];
    char                 *pw;
    char                 *pread;
    resty_client_header   header;
    int                   len, totle_len, no_read;
    int                   remain = 0;
    int                   wait = 5;
    
    status = R_BEGIN;
    begin_t = time(0);
    execute_t = begin_t;

    
    /* wait for return */
    //printf("Return data:\n");

    do {
        execute_t = time(0);
        usleep(20);
        totle_len = recv(ctx->fd, buffer, BUFFER_SIZE, 0);
        if(totle_len < 0) {
            printf("\nProblem:\n");
            printf("Error: %s\n", strerror(errno));
            break;
        } else if (totle_len == 0) {
            //printf("Error: %s\n", strerror(errno));
            break;
        }

        no_read = totle_len;
        pread = buffer;
        while (no_read || status == R_FINISH) {
            switch (status) {
                case R_BEGIN:{
                    remain = HEADER_SIZE;
                    len = HEADER_SIZE < no_read ? HEADER_SIZE : no_read;
                    memmove(&header, pread, len);
                    remain -= len;
                    no_read -= len;
                    pread += len;
                    if (remain == 0) {
                        pw = malloc(header.len);
                        remain = header.len;
                        status = R_BODY;
                    } else {
                        status = R_HEADER;
                    }
                    break;
                }
                case R_HEADER:{
                    len = remain < no_read ? remain : no_read;
                    memmove(&header + (HEADER_SIZE - remain), pread, len);
                    remain -= len;
                    no_read -= len;
                    pread += len;
                    if (remain == 0) {
                        pw = malloc(header.len);
                        remain = header.len;
                        status = R_BODY;
                    }
                    break;
                }
                case R_BODY:{
                    len = remain < no_read ? remain : no_read;
                    memmove(pw + (header.len - remain), pread, len);
                    remain -= len;
                    no_read -= len;
                    pread += len;
                    if (remain == 0) {
                        status = R_FINISH;
                    }
                    break;
                }
                case R_FINISH:{
                    fwrite(pw ,1 ,header.len ,stdout);
                    free(pw);
                    remain = 0;
                    status = R_BEGIN;
                    break;
                }
            }
        }

    }while(execute_t - begin_t <= wait);
    
    if (execute_t - begin_t > wait) {
        printf("Time out!\n");
    }

    return RESTY_CLI_OK;
}

int main(int argc, char *argv[])
{
    resty_client_context *ctx, context;

    ctx = &context;

    get_args(argc, argv, ctx);
    connection(ctx);
    sender(ctx);
    receiver(ctx);


    close(ctx->fd);
    if (ctx->type == RESTY_CLI_FILE) {
        free(ctx->code);
    }

    exit(EXIT_SUCCESS);
}
