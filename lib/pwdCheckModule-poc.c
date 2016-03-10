/*
 *  BOFH OpenLDAP PPolicy pwdCheckModules
 *  Copyright (C) 2016 Bindle Binaries <syzdek@bindlebinaries.com>.
 *  All rights reserved.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_START@
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
 */
/*
 *  Compile with:
 *     gcc -W -Wall -Werror -c -fPIC pwdCheckModule-poc.c
 *     gcc -shared -o pwdCheckModule-poc.so pwdCheckModule-poc.o
 *     cp pwdCheckModule-poc.so /openldap/prefix/libexec/openldap/
 */


#include <stdio.h>
#include <ldap.h>
#include <lber.h>
#include <string.h>
#include <inttypes.h>

typedef struct Entry Entry;

int check_password (char *pPasswd, char **ppErrStr, Entry *pEntry);

int check_password (char *pPasswd, char **ppErrStr, Entry *pEntry)
{
   size_t  pos;
   size_t  digit;
   size_t  upper;
   size_t  lower;
   size_t  special;
   size_t  pwlen;
   size_t  traits;
   size_t  charcount;
   size_t ascii[128];

   digit   = 0;
   upper   = 0;
   lower   = 0;
   special = 0;
   pwlen   = 0;

   memset(ascii, 0, sizeof(ascii));

   // check function arguments
   if (!(pPasswd))
      return(LDAP_OTHER);
   if (!(ppErrStr))
      return(LDAP_OTHER);
   if (!(pEntry))
      return(LDAP_OTHER);

   // gather password length and traits
   for(pwlen = 0; pPasswd[pwlen] != '\0'; pwlen++)
   {
      // count upper case, lower case, digits, and special characters
      if ((pPasswd[pwlen] >= 'A') && (pPasswd[pwlen] <= 'Z'))
         upper++;
      else if ((pPasswd[pwlen] >= 'a') && (pPasswd[pwlen] <= 'z'))
         lower++;
      else if ((pPasswd[pwlen] >= '0') && (pPasswd[pwlen] <= '9'))
         digit++;
      else
         special++;

      // count each instance of a character
      if ((pPasswd[pwlen] > 31) && (pPasswd[pwlen] < 127))
      {
         pos = (size_t)pPasswd[pwlen];
         if (ascii[pos] < 254)
            ascii[pos]++;
      };
   };

   // determine if a specific character is over 25% of the characters
   charcount = 0;
   for (pos = 31; pos < 127; pos++)
   {
      if (((ascii[pos] * 100) / pwlen) > 25)
      {
         *ppErrStr = strdup("Password contains too many duplicate characters");
         return(LDAP_OTHER);
      };
      if (ascii[pos] > 0)
         charcount++;
   };

   // verify a sufficient number of unique characters relative to the password's length
   if ( (((charcount * 100) / pwlen) < 60) && (pwlen < 16))
   {
      *ppErrStr = strdup("Password does not contain enough unique characters");
      return(LDAP_OTHER);
   }
   else if ( (((charcount * 100) / pwlen) < 50) && (pwlen < 32))
   {
      *ppErrStr = strdup("Password does not contain enough unique characters");
      return(LDAP_OTHER);
   }
   else if ( (((charcount * 100) / pwlen) < 20) && (pwlen < 64))
   {
      *ppErrStr = strdup("Password does not contain enough unique characters");
      return(LDAP_OTHER);
   };

   // count the number of unique traits of the password
   traits  = 0;
   if (upper != 0)
      traits++;
   if (lower != 0)
      traits++;
   if (digit != 0)
      traits++;
   if (special != 0)
      traits++;

   // discard password which are too short
   if (pwlen < 8)
   {
      *ppErrStr = strdup("Passwords must be at least 8 characters long");
      return(LDAP_OTHER);
   };

   // impose restrictions for 8 - 15 character passwords
   if ((pwlen < 16) && (traits < 3))
   {
      *ppErrStr = strdup("Passwords less than 16 characters require at least 3 traits (upper case, lower case, digits, or special characters)");
      return(LDAP_OTHER);
   };

   // impose restrictions for passwords over 15 characters
   if ((pwlen >= 16) && (traits < 2))
   {
      *ppErrStr = strdup("Passwords longer than 15 characters require at least 2 traits (upper case, lower case, digits, or special characters)");
      return(LDAP_OTHER);
   };

   // probably an okay password
   return(LDAP_SUCCESS);
}
