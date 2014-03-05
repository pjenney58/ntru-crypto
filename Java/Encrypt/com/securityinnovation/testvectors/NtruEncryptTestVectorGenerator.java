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

package com.securityinnovation.testvectors;

import java.util.Arrays;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import com.securityinnovation.util.Dump;
import com.securityinnovation.util.BitPack;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.OIDMap;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.digest.sha256;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import com.securityinnovation.jNeo.ntruencrypt.TVDump;

public class NtruEncryptTestVectorGenerator
{
    private static byte[] makeSeed(
        OID    oid,
        String usage)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        out.writeBytes(oid.toString());
        out.writeBytes(" ");
        out.writeBytes(usage);
        out.close();
        byte b[] = bos.toByteArray();
        bos.close();

        // hash it
        sha256 s = new sha256();
        byte b2[] = new byte[s.getDigestLen()];
        s.digest(b, 0, b.length, b2, 0);
        return b2;
    }

    public static byte m[] = {0x41, 0x42, 0x43};

    public static void main(String args[])
        throws NtruException, IOException
    {
        for (OID oid : OID.values())
        {
            TVDump.setOID(oid);
            byte oidBytes[] = OIDMap.getOIDBytes(oid);
            System.out.println("    // OID = " + oid + "  " +
                               oidBytes[0] + "." +
                               oidBytes[1] + "." +
                               oidBytes[2]);

            byte seed[] = makeSeed(oid, "keygen");
            TVDump.dumpHex("keygenSeed", seed);
            Random r = new Random(seed);
            NtruEncryptKey key = NtruEncryptKey.genKey(oid, r);

            seed = makeSeed(oid, "encrypt");
            TVDump.dumpHex("encryptSeed", seed);
            r.seed(seed);
            byte ct[] = key.encrypt(m, r);
            key.decrypt(ct);

            System.out.println("\n\n");
        }
    }
}
