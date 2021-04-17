#include <stdio.h>

int a = 0;

int main (int argc, char *argv[])
{
  if ( argc < 2 )
  {
    printf("No output file.\n");
    return -1;
  }

  printf("argc %d, argv[1] %s\n", argc, argv[1]);

  FILE* fid = fopen(argv[1], "w");

  for ( unsigned i = 0; i < 10; i++ )
  {
    a += i;
  }

  fprintf(fid, "%d\n", a);

  fclose(fid);
}
