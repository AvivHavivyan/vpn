//
// Created by Aviv on 08/05/2022.
//

#include <ctype.h>
#include <string.h>
#include "utils.h"
char * lowerstring(char * str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = (char)tolower((int)str[i]);
    }
    return str;
}