// Copyright 2024 Michael Conrad.
// Licensed under the Apache License, Version 2.0.
// See LICENSE file for details.

using System;
using System.Collections.Generic;

namespace DnsClient.Protocol.Options.OptOptions
{
    /* https://datatracker.ietf.org/doc/rfc8914/
     *2.  Extended DNS Error EDNS0 Option Format

       This document uses an Extended Mechanism for DNS (EDNS0) [RFC6891]
       option to include Extended DNS Error (EDE) information in DNS
       messages.  The option is structured as follows:

                                                    1   1   1   1   1   1
            0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       0: |                            OPTION-CODE                        |
          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       2: |                           OPTION-LENGTH                       |
          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       4: | INFO-CODE                                                     |
          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       6: / EXTRA-TEXT ...                                                /
          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

       Field definition details:

       OPTION-CODE:
          2 octets / 16 bits (defined in [RFC6891]) contains the value 15
          for EDE.

       OPTION-LENGTH:
          2 octets / 16 bits (defined in [RFC6891]) contains the length of
          the payload (everything after OPTION-LENGTH) in octets and should
          be 2 plus the length of the EXTRA-TEXT field (which may be a zero-
          length string).

       INFO-CODE:
          16 bits, which is the principal contribution of this document.
          This 16-bit value, encoded in network most significant bit (MSB)
          byte order, provides the additional context for the RESPONSE-CODE
          of the DNS message.  The INFO-CODE serves as an index into the
          "Extended DNS Errors" registry, defined and created in
          Section 5.2.

       EXTRA-TEXT:
          a variable-length, UTF-8-encoded [RFC5198] text field that may
          hold additional textual information.  This information is intended
          for human consumption (not automated parsing).  EDE text may be
          null terminated but MUST NOT be assumed to be; the length MUST be
          derived from the OPTION-LENGTH field.  The EXTRA-TEXT field may be
          zero octets in length, indicating that there is no EXTRA-TEXT
          included.  Care should be taken not to include private information
          in the EXTRA-TEXT field that an observer would not otherwise have
          access to, such as account numbers.

       The Extended DNS Error (EDE) option can be included in any response
       (SERVFAIL, NXDOMAIN, REFUSED, even NOERROR, etc.) to a query that
       includes an OPT pseudo-RR [RFC6891].  This document includes a set of
       initial codepoints but is extensible via the IANA registry defined
       and created in Section 5.2.
     */
    public class EDEOption : OptBaseOption
    {
        public override OptOption Code => OptOption.EDE;

        public EDECodes InfoCode { get; set; }

        public ushort RawInfoCode { get; set; }

        public string ExtraText { get; set; }


        public override string RecordToString()
        {
            return
                $"{this.Code.ToString()}: {(InfoCode != EDECodes.Unknown && PrettyPrintDNSSEC.TryGetValue(InfoCode, out var prettyPrintCode) ? prettyPrintCode : $"{RawInfoCode}")} {(String.IsNullOrWhiteSpace(ExtraText) == false ? $": ({ExtraText})" : string.Empty)}";
        }
        private static readonly Dictionary<EDECodes, string> PrettyPrintDNSSEC = new Dictionary<EDECodes, string>
        {
            { EDECodes.OtherError, "0 (Other Error)" },
            { EDECodes.UnsupportedDNSKEYAlgorithm, "1 (Unsupported DNSKEY Algorithm)" },
            { EDECodes.UnsupportedDSDigestType, "2 (Unsupported DS Digest Type)" },
            { EDECodes.StaleAnswer, "3 (Stale Answer)" },
            { EDECodes.ForgedAnswer, "4 (Forged Answer)" },
            { EDECodes.DNSSECIndeterminate, "5 (DNSSEC Indeterminate)" },
            { EDECodes.DNSSECBogus, "6 (DNSSEC Bogus)" },
            { EDECodes.SignatureExpired, "7 (Signature Expired)" },
            { EDECodes.SignatureNotYetValid, "8 (Signature Not Yet Valid)" },
            { EDECodes.DNSKEYMissing, "9 (DNSKEY Missing)" },
            { EDECodes.RRSIGsMissing, "10 (RRSIGs Missing)" },
            { EDECodes.NoZoneKeyBitSet, "11 (No Zone Key Bit Set)" },
            { EDECodes.NSECMissing, "12 (NSEC Missing)" },
            { EDECodes.CachedError, "13 (Cached Error)" },
            { EDECodes.NotReady, "14 (Not Ready)" },
            { EDECodes.Blocked, "15 (Blocked)" },
            { EDECodes.Censored, "16 (Censored)" },
            { EDECodes.Filtered, "17 (Filtered)" },
            { EDECodes.Prohibited, "18 (Prohibited)" },
            { EDECodes.StaleNXDomainAnswer, "19 (Stale NXDomain Answer)" },
            { EDECodes.NotAuthoritative, "20 (Not Authoritative)" },
            { EDECodes.NotSupported, "21 (Not Supported)" },
            { EDECodes.NoReachableAuthority, "22 (No Reachable Authority)" },
            { EDECodes.NetworkError, "23 (Network Error)" },
            { EDECodes.InvalidData, "24 (Invalid Data)" },
        };


    }

    public enum EDECodes
    {
        Unknown = -1,
        OtherError = 0,
        UnsupportedDNSKEYAlgorithm = 1,
        UnsupportedDSDigestType = 2,
        StaleAnswer = 3,
        ForgedAnswer = 4,
        DNSSECIndeterminate = 5,
        DNSSECBogus = 6,
        SignatureExpired = 7,
        SignatureNotYetValid = 8,
        DNSKEYMissing = 9,
        RRSIGsMissing = 10,
        NoZoneKeyBitSet = 11,
        NSECMissing = 12,
        CachedError = 13,
        NotReady = 14,
        Blocked = 15,
        Censored = 16,
        Filtered = 17,
        Prohibited = 18,
        StaleNXDomainAnswer = 19,
        NotAuthoritative = 20,
        NotSupported = 21,
        NoReachableAuthority = 22,
        NetworkError = 23,
        InvalidData = 24,
    }

}
