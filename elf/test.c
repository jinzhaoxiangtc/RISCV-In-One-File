#include <stdio.h>

int main ()
{
  int sum = 0;

  for ( unsigned i = 0; i < 10; i++ )
    sum += i;

  printf("Sum = %d\n", sum);
}
