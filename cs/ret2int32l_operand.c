 #include <stdio.h>

    int main(void){
            int l, x;

            l = 0x40000000;

            printf("l = %d (0x%x)\n", l, l);

            x = l + 0xc0000000;
            printf("l + 0xc0000000 = %d (0x%x)\n", x, x);

            x = l * 0x4;
            printf("l * 0x4 = %d (0x%x)\n", x, x);

            x = l - 0xffffffff;
            printf("l - 0xffffffff = %d (0x%x)\n", x, x);

            return 0;
    }
