#include <stdio.h>
#include <stdlib.h>

#define BASENAME "AUTO_localhost_8888_-.sct"
#define DIRNAME  "d9863e419fc90a7faab64952d3d71a389734f82214fb3817cb5c88be81c2f1cb"

int main(void)
{
    char *destdir;

    system("copy %HOME%\\" BASENAME " %TEMP%\\" DIRNAME "\\");
    destdir = getenv("TEMP");
    if (!destdir) {
        fprintf(stderr, "TEMP isn't set\n");
        return 1;
    }

    /* "touch" idiom on Windows 7 requires setting the current directory to the
     * one with the file to "touch"
     */
    destdir = malloc(strlen(getenv("TEMP")) + strlen("\\" DIRNAME) + 1);
    strcpy(destdir, getenv("TEMP"));
    strcat(destdir, "\\" DIRNAME);
    if (chdir(destdir) != 0) {
        fprintf(stderr, "couldn't change to %s\n", destdir);
        return 1;
    }

    system("copy /b " BASENAME " +,,");
    return 0;
}
