/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved.
 *
 * Copyright (C) 2009-2013  Security Innovation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *********************************************************************************/

/*
 * Contents: Tests for the SHA1 class.
 *
 * This just tests the correctness of the SHA algorithm by comparing
 * its output to known test vectors. The test vectors come from the
 * cryptolib library and are a combination of the FIPS 180-2 test
 * vectors and home-grown test vectors.
 */

package com.securityinnovation.jNeo.digest;

import org.junit.Test;
import static org.junit.Assert.*;

/////////////////////////////////////////////////////////////////////////
// Tests:
//   - getDigestLen
//       - check correct length
//   - getBlockLen
//       - check correct length
//   - reset
//       - use on partial digest
//       - use on finished digest
//       - multiple use
//   - update
//       - null buffer
//       - negative offset
//       - negative length
//       - offset+length overrun buffer end
//       - calling multiple times on split buffers is the same as calling
//         once on full buffer.
//   - finishDigest
//       - null buffer
//       - negative offset
//       - offset+output length overrun buffer end
//       - verify object is left reinitialized for new hash operation
//   - known-value tests. These are positive tests for update and finishDigest.

public class Sha1BBTestCase {

    /////////////////////////////////////////////////////////////////////////
    // Test getDigestLen
    // 
    // Implements test case SGD-1.
    @Test public void test_getDigestLen()
    {
        Sha1 s = new Sha1();
        assertEquals(20, s.getDigestLen());
    }


    /////////////////////////////////////////////////////////////////////////
    // Test getBlockLen
    // 
    // Implements test case SGB-1.
    @Test public void test_getBlockLen()
    {
        Sha1 s = new Sha1();
        assertEquals(64, s.getBlockLen());
    }


    /////////////////////////////////////////////////////////////////////////
    // Test reset
    // 
    // Implements test case SRS-1.
    // reset:  use on partial digest
    @Test public void test_reset_partial_state()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 128);
        s.reset();
        s.update(sha1_in, 0, 126);
        assertArrayEquals(sha1_ans126, s.finishDigest());
    }
    // reset:  use on finished digest
    @Test public void test_reset_finished_digest()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 128);
        s.finishDigest();
        s.reset();
        s.update(sha1_in, 0, 126);
        assertArrayEquals(sha1_ans126, s.finishDigest());
    }
    // reset:  multiple use
    @Test public void test_reset_multiple_use()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 128);
        s.finishDigest();
        s.reset();
        s.reset();
        s.reset();
        s.update(sha1_in, 0, 126);
        assertArrayEquals(sha1_ans126, s.finishDigest());
    }


    /////////////////////////////////////////////////////////////////////////
    // Test update
    // 
    // Implements test case SUP-2.
    @Test(expected=NullPointerException.class)
    public void test_update_null()
    {
        Sha1 s = new Sha1();
        s.update(null, 0, 2);
    }
    
    // Implements test case SUP-5.
    @Test(expected=IllegalArgumentException.class)
    public void test_update_negativeOffset()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, -1, 10);
    }
    
    // Implements test case SUP-4.
    @Test(expected=IllegalArgumentException.class)
    public void test_update_negativeLength()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, -1);
    }
    
    // Implements test case SUP-6.
    @Test(expected=IllegalArgumentException.class)
    public void test_update_overrun()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 1, sha1_in.length);
    }
    
    // Implements test case SUP-3.
    @Test public void test_update_length_zero()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 0);
    }

    // Implements test case SUP-1.
    // update:  calling multiple times on split buffers is the same as calling
    //          once on full buffer.
    @Test public void test_update_multple_buffers()
    {
        Sha1 s = new Sha1();
        for (int i=0; i<56; i++)
          s.update(sha1_in, i, 1);
        assertArrayEquals(sha1_ans56, s.finishDigest());
    }


    /////////////////////////////////////////////////////////////////////////
    // Test finishDigest
    //
    // Implements test case SFD-2
    public void test_finishDigest_reset()
    {
        Sha1 s = new Sha1();
        byte b[] = new byte[20];

        // Hash some misc data and finish the computation
        java.util.Arrays.fill(b, (byte)0);
        s.update(b, 0, 10);
        s.finishDigest(b, 0);

        // Hash some new data. Verify the output doesn't depend on the previous hash
        s.update(sha1_in, 0, 3);
        s.finishDigest(b, 0);
        assertArrayEquals(sha1_ans3, b);
    }

    // Implements test case SFD-3.
    @Test(expected=NullPointerException.class)
    public void test_finishDigest_null()
    {
        Sha1 s = new Sha1();
        s.finishDigest(null, 0);
    }
    
    // Implements test case SFD-4.
    @Test(expected=IllegalArgumentException.class)
    public void test_finishDigest_negativeOffset()
    {
        Sha1 s = new Sha1();
        byte b[] = new byte[20];
        java.util.Arrays.fill(b, (byte)0);
        s.finishDigest(b, -1);
    }
    
    // Implements test case SFD-5.
    @Test(expected=IllegalArgumentException.class)
    public void test_finishDigest_overrun()
    {
        Sha1 s = new Sha1();
        byte b[] = new byte[19];
        java.util.Arrays.fill(b, (byte)0);
        s.finishDigest(b, 0);
    }


    /////////////////////////////////////////////////////////////////////////
    // Known-value tests. These are positive tests for update and finishDigest.
    // Implements test cases SHC-1, SFD-1, SFD-2, and SUP-1.
    //
    @Test public void test_0_bytes()
    {
        Sha1 s = new Sha1();
        assertArrayEquals(sha1_ans0, s.finishDigest());
    }
    @Test public void test_3_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 3);
        assertArrayEquals(sha1_ans3, s.finishDigest());
    }
    @Test public void test_55_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 55);
        assertArrayEquals(sha1_ans55, s.finishDigest());
    }
    @Test public void test_56_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 56);
        assertArrayEquals(sha1_ans56, s.finishDigest());
    }
    @Test public void test_63_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 63);
        assertArrayEquals(sha1_ans63, s.finishDigest());
    }
    @Test public void test_64_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 64);
        assertArrayEquals(sha1_ans64, s.finishDigest());
    }
    @Test public void test_126_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 126);
        assertArrayEquals(sha1_ans126, s.finishDigest());
    }
    @Test public void test_128_bytes()
    {
        Sha1 s = new Sha1();
        s.update(sha1_in, 0, 128);
        assertArrayEquals(sha1_ans128, s.finishDigest());
    }
    @Test public void test_1000000_bytes()
    {
        Sha1 s = new Sha1();
        for (int i=0; i<1000; i++)
          s.update(sha1_in_a, 0, sha1_in_a.length);
        assertArrayEquals(sha1_ans1000000, s.finishDigest());
    }



    static final byte sha1_in[] = {
        (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
        (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65,
        (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66,
        (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x6f, (byte)0x70, (byte)0x71, (byte)0x72,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74,
        (byte)0x72, (byte)0x73, (byte)0x64, (byte)0x65,
        (byte)0x73, (byte)0x74, (byte)0x75, (byte)0x76,
        (byte)0x74, (byte)0x75, (byte)0x76, (byte)0x77,
        (byte)0x75, (byte)0x76, (byte)0x77, (byte)0x78,
        (byte)0x76, (byte)0x77, (byte)0x78, (byte)0x79,
        (byte)0x77, (byte)0x78, (byte)0x79, (byte)0x7a,
        (byte)0x78, (byte)0x79, (byte)0x7a, (byte)0x7b,
        (byte)0x79, (byte)0x7a, (byte)0x7b, (byte)0x7c,
        (byte)0x7a, (byte)0x7b, (byte)0x7c, (byte)0x7d,
        (byte)0x7b, (byte)0x7c, (byte)0x7d, (byte)0x7e,
        (byte)0x7c, (byte)0x7d, (byte)0x7e, (byte)0x7f,
        (byte)0x7d, (byte)0x7e, (byte)0x7f, (byte)0x80,
        (byte)0x7e, (byte)0x7f, (byte)0x80, (byte)0x81,
        (byte)0x7f, (byte)0x80, (byte)0x81, (byte)0x82,
        (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83,
    };
    
    static final byte sha1_ans0[] = {
        (byte)0xda, (byte)0x39, (byte)0xa3, (byte)0xee,
        (byte)0x5e, (byte)0x6b, (byte)0x4b, (byte)0x0d,
        (byte)0x32, (byte)0x55, (byte)0xbf, (byte)0xef,
        (byte)0x95, (byte)0x60, (byte)0x18, (byte)0x90,
        (byte)0xaf, (byte)0xd8, (byte)0x07, (byte)0x09,
    };

    static final byte sha1_ans3[] = {
        (byte)0xa9, (byte)0x99, (byte)0x3e, (byte)0x36,
        (byte)0x47, (byte)0x06, (byte)0x81, (byte)0x6a,
        (byte)0xba, (byte)0x3e, (byte)0x25, (byte)0x71,
        (byte)0x78, (byte)0x50, (byte)0xc2, (byte)0x6c,
        (byte)0x9c, (byte)0xd0, (byte)0xd8, (byte)0x9d,
    };

    static final byte sha1_ans55[] = {
        (byte)0x47, (byte)0xb1, (byte)0x72, (byte)0x81,
        (byte)0x07, (byte)0x95, (byte)0x69, (byte)0x9f,
        (byte)0xe7, (byte)0x39, (byte)0x19, (byte)0x7d,
        (byte)0x1a, (byte)0x1f, (byte)0x59, (byte)0x60,
        (byte)0x70, (byte)0x02, (byte)0x42, (byte)0xf1,
    };

    static final byte sha1_ans56[] = {
        (byte)0x84, (byte)0x98, (byte)0x3e, (byte)0x44,
        (byte)0x1c, (byte)0x3b, (byte)0xd2, (byte)0x6e,
        (byte)0xba, (byte)0xae, (byte)0x4a, (byte)0xa1,
        (byte)0xf9, (byte)0x51, (byte)0x29, (byte)0xe5,
        (byte)0xe5, (byte)0x46, (byte)0x70, (byte)0xf1,
    };

    static final byte sha1_ans63[] = {
        (byte)0x9f, (byte)0x47, (byte)0xf2, (byte)0x5c,
        (byte)0xec, (byte)0xf2, (byte)0x4d, (byte)0x24,
        (byte)0x66, (byte)0xa6, (byte)0x7f, (byte)0x96,
        (byte)0x9e, (byte)0xd0, (byte)0x36, (byte)0x93,
        (byte)0xcb, (byte)0xbd, (byte)0x7f, (byte)0x66,
    };

    static final byte sha1_ans64[] = {
        (byte)0x79, (byte)0xea, (byte)0x0c, (byte)0x76,
        (byte)0xf0, (byte)0x05, (byte)0x63, (byte)0x73,
        (byte)0xff, (byte)0xd6, (byte)0xa5, (byte)0xaa,
        (byte)0xd3, (byte)0x89, (byte)0xdd, (byte)0x90,
        (byte)0x8b, (byte)0x0c, (byte)0x0e, (byte)0x94,
    };

    static final byte sha1_ans126[] = {
        (byte)0xeb, (byte)0x2f, (byte)0x5b, (byte)0x97,
        (byte)0x83, (byte)0xb4, (byte)0x01, (byte)0x32,
        (byte)0xd4, (byte)0xb6, (byte)0xda, (byte)0x88,
        (byte)0xda, (byte)0x74, (byte)0x44, (byte)0x28,
        (byte)0x95, (byte)0x57, (byte)0x0c, (byte)0xe5,
    };

    static final byte sha1_ans128[] = {
        (byte)0x2f, (byte)0x93, (byte)0x5b, (byte)0xda,
        (byte)0x58, (byte)0x18, (byte)0x9e, (byte)0x97,
        (byte)0x6c, (byte)0x1c, (byte)0xd2, (byte)0xfa,
        (byte)0x6a, (byte)0xa6, (byte)0xce, (byte)0xd2,
        (byte)0x0d, (byte)0x46, (byte)0x1c, (byte)0xe6,
    };

    static final byte sha1_in_a[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    };

    static final byte sha1_ans1000000[] = {
        (byte)0x34, (byte)0xaa, (byte)0x97, (byte)0x3c,
        (byte)0xd4, (byte)0xc4, (byte)0xda, (byte)0xa4,
        (byte)0xf6, (byte)0x1e, (byte)0xeb, (byte)0x2b,
        (byte)0xdb, (byte)0xad, (byte)0x27, (byte)0x31,
        (byte)0x65, (byte)0x34, (byte)0x01, (byte)0x6f,
    };
}
