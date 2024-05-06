> Works on paiza, but not in the actual kernel.

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_string_as_hex(char *str) {
    if (str == NULL) {
        return -1;
    }
    
    {
        size_t len =  strlen(str);
        char *hex = malloc(len * 2 + 1);
        
        for (size_t i = 0; i < len; ++i) {
            hex[i * 2] = "0123456789ABCDEF"[str[i] >> 4];
            hex[i * 2 + 1] = "0123456789ABCDEF"[str[i] & 0x0F];
        }
        
        hex[len * 2] = '\0';
        strcpy(str, hex);
        free(hex);
        return 0;
    }
}

int get_hex_as_string(char* hex) {
    if (hex == NULL) {
        return -1;
    }
    
    {
        size_t len = strlen(hex) / 2;
        char *str = malloc(len + 1);
        size_t i;
        
        for (i = 0; i < len; ++i) {
            sscanf(&hex[i * 2], "%02x", &str[i]);
        }
        
        str[len] = '\0';
        strcpy(hex, str);
        free(str);
        return 0;
    }
}

int main(void){
    char * test = malloc(26);
    strcpy(test, "Hello World");

    int res = 0;
    printf("1: %s - %s\n", test, test);
    
    res = get_string_as_hex(test);
    
    if (res == -1) {
        printf("-1");
        return -1;
    }
    
    printf("3: %s\n", test);
    
    res = get_hex_as_string(test);
    
    if (res == -1) {
        printf("-1");
        return -1;
    }
    
    printf("4: %s\n", test);
}

```