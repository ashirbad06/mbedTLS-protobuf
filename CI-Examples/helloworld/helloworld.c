#include <stdio.h>
#include <stdlib.h>

int main() {
    char *KII_TUPLES_PER_JOB = getenv("KII_TUPLES_PER_JOB");
    char *KII_SHARED_FOLDER = getenv("KII_SHARED_FOLDER");
    char *KII_TUPLE_FILE = getenv("KII_TUPLE_FILE");
    char *KII_PLAYER_NUMBER = getenv("KII_PLAYER_NUMBER");
    char *KII_PLAYER_COUNT = getenv("KII_PLAYER_COUNT");
    char *KII_JOB_ID = getenv("KII_JOB_ID");
    char *KII_TUPLE_TYPE = getenv("KII_TUPLE_TYPE");
    char *KII_PLAYER_ENDPOINT_1 = getenv("KII_PLAYER_ENDPOINT_1");
    char *KII_PLAYER_ENDPOINT_0 = getenv("KII_PLAYER_ENDPOINT_0");

    printf("Hello!!!!!!!!!!!\n");

    // Check the status of each environment variable
    if (KII_TUPLES_PER_JOB != NULL) {
        printf("KII_TUPLES_PER_JOB=%s\n", KII_TUPLES_PER_JOB);
    } else {
        fprintf(stderr, "Error: Environment variable KII_TUPLES_PER_JOB not found.\n");
    }

    if (KII_SHARED_FOLDER != NULL) {
        printf("KII_SHARED_FOLDER=%s\n", KII_SHARED_FOLDER);
    } else {
        fprintf(stderr, "Error: Environment variable KII_SHARED_FOLDER not found.\n");
    }

    if (KII_TUPLE_FILE != NULL) {
        printf("KII_TUPLE_FILE=%s\n", KII_TUPLE_FILE);
    } else {
        fprintf(stderr, "Error: Environment variable KII_TUPLE_FILE not found.\n");
    }

    if (KII_PLAYER_NUMBER != NULL) {
        printf("KII_PLAYER_NUMBER=%s\n", KII_PLAYER_NUMBER);
    } else {
        fprintf(stderr, "Error: Environment variable KII_PLAYER_NUMBER not found.\n");
    }

    if (KII_PLAYER_COUNT != NULL) {
        printf("KII_PLAYER_COUNT=%s\n", KII_PLAYER_COUNT);
    } else {
        fprintf(stderr, "Error: Environment variable KII_PLAYER_COUNT not found.\n");
    }

    if (KII_JOB_ID != NULL) {
        printf("KII_JOB_ID=%s\n", KII_JOB_ID);
    } else {
        fprintf(stderr, "Error: Environment variable KII_JOB_ID not found.\n");
    }

    if (KII_TUPLE_TYPE != NULL) {
        printf("KII_TUPLE_TYPE=%s\n", KII_TUPLE_TYPE);
    } else {
        fprintf(stderr, "Error: Environment variable KII_TUPLE_TYPE not found.\n");
    }

    if (KII_PLAYER_ENDPOINT_1 != NULL) {
        printf("KII_PLAYER_ENDPOINT_1=%s\n", KII_PLAYER_ENDPOINT_1);
    } else {
        fprintf(stderr, "Error: Environment variable KII_PLAYER_ENDPOINT_1 not found.\n");
    }

    if (KII_PLAYER_ENDPOINT_0 != NULL) {
        printf("KII_PLAYER_ENDPOINT_0=%s\n", KII_PLAYER_ENDPOINT_0);
    } else {
        fprintf(stderr, "Error: Environment variable KII_PLAYER_ENDPOINT_0 not found.\n");
    }

    return 0;
}
