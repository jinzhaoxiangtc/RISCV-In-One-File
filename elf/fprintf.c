#include <stdio.h>

int a = 0;

int main (int argc, char *argv[])
{
  FILE* fid = fopen(argv[1], "w+");

  printf("argc %d, argv[1] %s\n", argc, argv[1]);

  for ( unsigned i = 0; i < 10; i++ )
  {
    a += i;
  }

  fprintf(fid, "%d\n", a);

  fclose(fid);
}
