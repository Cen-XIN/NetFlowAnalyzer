/*
 * Version 1.0.2 (2018-07-06)
 * Copyright (c) Cen XIN
 */
#include "analysis.h"

int main() {
    int func;

    printf("*****************************************\n");
    printf("*  Welcome to                           *\n");
    printf("*        Network Data Flow              *\n");
    printf("*                     Analyzing System  *\n");
    printf("*****************************************\n");
    printf("*          Designed by XIN CEN          *\n");
    printf("*****************************************\n");
    printf("*           CS&T1501 COI HZAU           *\n");
    printf("*****************************************\n\n");
    printf("+---------------------------------------+\n");
    printf("| What would you like to do? :)         |\n");
    printf("+---------------------------------------+\n");
    printf("| Enter 1 for monitor net flow          |\n");
    printf("+---------------------------------------+\n");
    printf("| Enter 2 for catch and analyse network |\n");
    printf("+---------------------------------------+\n");
    printf(">");
    scanf("%d", &func);

    switch (func) {
        case 1:
            start_monitor();
            break;
        case 2:
            start_analyse();
            break;
        default:
            printf("Wrong instruction! :(\n");
            break;
    }

    printf("Exit...\n\n");
    return 0;
}