/*
 * password.h
 *
 * Copyright (C) 2007, 2008, 2009, 2013
 *
 * This software is licensed as "freeware."  Permission to distribute
 * this software in source and binary forms is hereby granted without a
 * fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
 * THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
 * BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
 *
 */

#ifndef AESCRYPT_PASSWORD_H
#define AESCRYPT_PASSWORD_H

#define MAX_PASSWD_LEN  1024
#define MAX_PASSWD_BUF  2050 /* MAX_PASSWD_LEN * 2 + 2 -- UTF-16 */

typedef enum {UNINIT, DEC, ENC} encryptmode_t;

/*
 * Error codes for read_password function.
 */
#define AESCRYPT_READPWD_FOPEN       -1
#define AESCRYPT_READPWD_FILENO      -2
#define AESCRYPT_READPWD_TCGETATTR   -3
#define AESCRYPT_READPWD_TCSETATTR   -4
#define AESCRYPT_READPWD_FGETC       -5
#define AESCRYPT_READPWD_TOOLONG     -6
#define AESCRYPT_READPWD_NOMATCH     -7

/*
 * Function Prototypes
 */
int passwd_to_utf16(unsigned char *in_passwd,
                    int length,
                    int max_length,
                    unsigned char *out_passwd);

const char* read_password_error(int error);

int read_password(unsigned char* buffer,
                  encryptmode_t mode);


#endif // AESCRYPT_PASSWORD_H
