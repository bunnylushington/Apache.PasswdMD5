Apache.PasswdMD5
=========

Provides a means of generating an Apache style MD5 hash (as used by
htaccess).  This code was derived from the Crypt::PasswdMD5 Perl
module which appears to have been based on 

  http://svn.apache.org/viewvc/apr/apr/trunk/crypto/apr_md5.c?view=co

# Examples

    iex> {:ok, magic, salt, pw, htstring} =
    ...>     Apache.PasswdMD5.crypt("password", "salt")
    {:ok, "$apr1$", "salt", "password", "$apr1$salt$Xxd1irWT9ycqoYxGFn4cb."}
    
    iex> {:ok, ^magic, ^salt, ^pw, ^htstring} =
    ...>     Apache.PasswdMD5.crypt("password", htstring)
    {:ok, "$apr1$", "salt", "password", "$apr1$salt$Xxd1irWT9ycqoYxGFn4cb."}


Many thanks to the long string of original authors.

If you encounter issues or have suggetions, please let me know.

------------

The MIT License (MIT)

Copyright (c) 2014 Kevin Montuori & BAPI Consulting.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
