riscv64-unknown-elf-gcc -S test.c
riscv64-unknown-elf-gcc -o test test.c
riscv64-unknown-elf-objdump -d test
spike -m256 -l --log-commits pk test
spike -m256 pk test
