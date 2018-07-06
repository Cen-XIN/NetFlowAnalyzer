/*
 * Version 1.0.2 (2018-07-06)
 * Copyright (c) Cen XIN
 */

#ifndef NETFLOWANALYZER_HASH_H
#define NETFLOWANALYZER_HASH_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE (1024 * 1024)

struct kv {
    struct kv *next;
    char *key;
    void *value;
    void (*free_value)(void*);
};

struct HashTable {
    struct kv **table;
};

/**
 * initialize kv struct
 * @param kv
 */
static void init_kv(struct kv *kv);

/**
 * free kv struct
 * @param kv
 */
static void free_kv(struct kv* kv);

/**
 * hash function time_33
 * @param key
 * @return
 */
static unsigned int hash_33(char *key);

/**
 * create a new hash table
 * @return
 */
struct HashTable *hash_table_new();

/**
 * delect an existing hash table
 * @param ht
 */
void hash_table_delete(struct HashTable* ht);

/**
 * put content into hash table
 * @param ht
 * @param key
 * @param value
 * @param free_value
 * @return
 */
int hash_table_put2(struct HashTable* ht, char *key, void *value, void(*free_value)(void*));

/**
 * get hash table
 * @param ht
 * @param key
 * @return
 */
void *hash_table_get(struct HashTable* ht, char *key);

/**
 * remove hash table
 * @param ht
 * @param key
 */
void hash_table_rm(struct HashTable* ht, char *key);

#endif //NETFLOWANALYZER_HASH_H
