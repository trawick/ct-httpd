#include <stdlib.h>

#define BASENAME "AUTO_localhost_8888_-.sct"
#define DIRNAME  "d9863e419fc90a7faab64952d3d71a389734f82214fb3817cb5c88be81c2f1cb"

int main(void)
{
    system("copy %HOME%\\" BASENAME " %TEMP%\\" DIRNAME "\\");
    system("powershell (ls %TEMP%\\" DIRNAME "\\" BASENAME ").LastWriteTime = Get-Date");
    return 0;
}
