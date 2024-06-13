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

    /// <summary>
    /// A <see cref="OptBaseOption"/> representing the Extended DNS Error (EDE) Option
    /// <seealso href="https://datatracker.ietf.org/doc/rfc8914">RFC 8914</seealso>
    /// </summary>
    public class EDEOption : OptBaseOption
    {
        /// <inheritdoc />
        public override OptOption Code => OptOption.EDE;

        /// <summary>
        /// Info-Code returned for the Extended DNS Error
        /// </summary>
        public EDECodes InfoCode { get; set; }

        /// <summary>
        /// Raw Info-Code returned for the Extended DNS Error. Will be set even if the code is unknown/non-standard.
        /// </summary>
        public int RawInfoCode { get; set; }

        /// <summary>
        /// Extra-Text from Extended DNS Error
        /// </summary>
        public string ExtraText { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            return RecordToString();
        }

        /// <inheritdoc />
        public override string RecordToString()
        {
            return
                $"{Code}: {(InfoCode != EDECodes.Unknown && s_prettyPrintDnssec.TryGetValue(InfoCode, out var prettyPrintCode) ? prettyPrintCode : $"{RawInfoCode}")} {(string.IsNullOrWhiteSpace(ExtraText) == false ? $": ({ExtraText})" : string.Empty)}";
        }
        private static readonly Dictionary<EDECodes, string> s_prettyPrintDnssec = new Dictionary<EDECodes, string>
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

    /// <summary>
    /// Extended DNS Errors Codes as defined in <see href="https://datatracker.ietf.org/doc/rfc8914">RFC 8914</see>
    /// </summary>
    public enum EDECodes
    {
        /// <summary>
        /// An unsupported/non-standard EDE Code.
        /// </summary>
        Unknown = -1,
        /// <summary>
        /// The error does not match known extended error codes. Extra Text may include more information.
        /// </summary>
        OtherError = 0,
        /// <summary>
        /// DNSKEY RRset contained only unsupported DNSSEC algorithms. 
        /// </summary>
        UnsupportedDNSKEYAlgorithm = 1,
        /// <summary>
        /// DS RRset contained only unsupported Digest Types.
        /// </summary>
        UnsupportedDSDigestType = 2,
        /// <summary>
        /// Stale Cached Response Returned, unable to get new data.
        /// </summary>
        StaleAnswer = 3,
        /// <summary>
        /// Answer provided but forged due to policy reasons.
        /// </summary>
        ForgedAnswer = 4,
        /// <summary>
        /// DNSSEC Validation ended in indeterminate state (RFC4035).
        /// </summary>
        DNSSECIndeterminate = 5,
        /// <summary>
        /// DNSSEC validation returned BOGUS state.
        /// </summary>
        DNSSECBogus = 6,
        /// <summary>
        /// DNSSEC Validation failed due to no signatures being valid, and some are expired.
        /// </summary>
        SignatureExpired = 7,
        /// <summary>
        /// DNSSEC Validation failed due to no signatures being valid, and at least some are not yet valid.
        /// </summary>
        SignatureNotYetValid = 8,
        /// <summary>
        /// DNSSEC Validation failed due to no matching DNSKEY being found for the child.
        /// </summary>
        DNSKEYMissing = 9,
        /// <summary>
        /// DNSSEC Validation failed due to no RRSIGs could be found for at least one RRset where RRSIGs were expected.
        /// </summary>
        RRSIGsMissing = 10,
        /// <summary>
        /// DNSSEC Validation failed due to no Zone Key bit being set in a DNSKEY.
        /// </summary>
        NoZoneKeyBitSet = 11,
        /// <summary>
        /// DNSSEC Validation failed due to the requested data being missing and a covering NSEC/NSEC3 was not provided
        /// </summary>
        NSECMissing = 12,
        /// <summary>
        /// The resolver is returning SERVFAIL from its cache
        /// </summary>
        CachedError = 13,
        /// <summary>
        /// The server is not ready to answer the query.
        /// </summary>
        NotReady = 14,
        /// <summary>
        /// The server is unable to answer due to a blocklist imposed by the operator of the server resolving or forwarding the query
        /// </summary>
        Blocked = 15,
        /// <summary>
        /// The server is unable to answer due to a blocklist due to an external requirement imposed by an entity other then the operator of the server resolving or forwarding the query (in-band DNS filtering, court order, etc.).
        /// </summary>
        Censored = 16,
        /// <summary>
        /// The server is unable to answer because the domain is on a blocklist as requested by the client.
        /// </summary>
        Filtered = 17,
        /// <summary>
        /// Client is not authorized to use this DNS Server.
        /// </summary>
        Prohibited = 18,
        /// <summary>
        /// The resolver responded with a previously cached NXDomain due to being unable to get new data.
        /// </summary>
        StaleNXDomainAnswer = 19,
        /// <summary>
        /// Recursion Resired (RD) bit clear, and the request was sent to an Authoritative Server which it is not Authoritive for, or the request was sen to a resolver.
        /// </summary>
        NotAuthoritative = 20,
        /// <summary>
        /// The requested operation or query is not supported.
        /// </summary>
        NotSupported = 21,
        /// <summary>
        ///    The resolver could not reach any of the authoritative name servers (or they potentially refused to reply).
        /// </summary>
        NoReachableAuthority = 22,
        /// <summary>
        ///  An unrecoverable error occurred while communicating with another server.
        /// </summary>
        NetworkError = 23,
        /// <summary>
        /// The authoritative server cannot answer with data for a zone it isotherwise configured to support.  Examples of this include its most recent zone being too old or having expired.
        /// </summary>
        InvalidData = 24,
    }

}
