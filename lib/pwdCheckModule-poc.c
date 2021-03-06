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
   size_t  uniquechars;
   size_t  lastdigits;
   size_t  ascii[128];

   digit       = 0;
   upper       = 0;
   lower       = 0;
   special     = 0;
   pwlen       = 0;
   uniquechars = 0;
   lastdigits  = 0;

   memset(ascii, 0, sizeof(ascii));

   // check function arguments
   if ( (!(pPasswd)) || (!(ppErrStr)) || (!(pEntry)) )
      return(LDAP_OTHER);

   // gather password length, traits, and character counts
   for(pwlen = 0; pPasswd[pwlen] != '\0'; pwlen++)
   {
      // count upper case, lower case, digits, and special characters
      if ((pPasswd[pwlen] >= 'A') && (pPasswd[pwlen] <= 'Z'))
      {
         lastdigits = 0;
         upper++;
      }
      else if ((pPasswd[pwlen] >= 'a') && (pPasswd[pwlen] <= 'z'))
      {
         lastdigits = 0;
         lower++;
      }
      else if ((pPasswd[pwlen] >= '0') && (pPasswd[pwlen] <= '9'))
      {
         lastdigits++;
         digit++;
      }
      else
      {
         lastdigits = 0;
         special++;
      };

      // count characters
      if ((pPasswd[pwlen] > 31) && (pPasswd[pwlen] < 127))
      {
         pos = (size_t)pPasswd[pwlen];

         // count unique characters
         if (ascii[pos] == 0)
            uniquechars++;

         // count each instance of a character
         if (ascii[pos] < 254)
            ascii[pos]++;
      };
   };

   // determine if a specific character is over 25% of the characters
   for (pos = 31; pos < 127; pos++)
   {
      if (((ascii[pos] * 100) / pwlen) > 25)
      {
         *ppErrStr = strdup("Password contains too many duplicate characters");
         return(LDAP_OTHER);
      };
   };

   // count the number of unique traits of the password
   traits  = 0;
   traits += (upper   != 0) ? 1 : 0;
   traits += (lower   != 0) ? 1 : 0;
   traits += (digit   != 0) ? 1 : 0;
   traits += (special != 0) ? 1 : 0;

   // discard passwords which are too short
   if (pwlen < 8)
   {
      *ppErrStr = strdup("Passwords must be at least 8 characters long");
      return(LDAP_OTHER);
   }

   // restrictions for 8 - 15 character passwords
   else if (pwlen < 16)
   {
      // do not allow passwords to end with 2 or 4 digits if only 8 characters
      if ( (pwlen == 8) && ((lastdigits == 2) || (lastdigits == 4)) )
      {
         *ppErrStr = strdup("8 character passwords may not end with 2 or more digits");
         return(LDAP_OTHER);
      };

      // require at least 3 password traits
      if (traits < 3)
      {
         *ppErrStr = strdup("Passwords less than 16 characters require at least 3 traits (upper case, lower case, digits, or special characters)");
         return(LDAP_OTHER);
      };

      // require at least 60% of characters be unique
      if (((uniquechars * 100) / pwlen) < 60)
      {
         *ppErrStr = strdup("Password does not contain enough unique characters");
         return(LDAP_OTHER);
      };
   }

   // restrictions 16  - 32 character passwords
   else if (pwlen < 32)
   {
      // require at least 2 password traits
      if (traits < 2)
      {
         *ppErrStr = strdup("Passwords longer than 15 characters require at least 2 traits (upper case, lower case, digits, or special characters)");
         return(LDAP_OTHER);
      };

      // require at least 50% of characters be unique
      if (((uniquechars * 100) / pwlen) < 50)
      {
         *ppErrStr = strdup("Password does not contain enough unique characters");
         return(LDAP_OTHER);
      };
   }

   // restrictions 32+ character passwords
   else
   {
      // require at least 2 password traits
      if (traits < 2)
      {
         *ppErrStr = strdup("Passwords longer than 15 characters require at least 2 traits (upper case, lower case, digits, or special characters)");
         return(LDAP_OTHER);
      };

      // require at least 20% of characters be unique
      if (((uniquechars * 100) / pwlen) < 20)
      {
         *ppErrStr = strdup("Password does not contain enough unique characters");
         return(LDAP_OTHER);
      };
   }

   // probably an okay password
   return(LDAP_SUCCESS);
}
