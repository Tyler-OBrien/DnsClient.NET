// Copyright 2024 Michael Conrad.
// Licensed under the Apache License, Version 2.0.
// See LICENSE file for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using DnsClient.Protocol;
using DnsClient.Protocol.Options;
using DnsClient.Protocol.Options.OptOptions;

#if NET8_0_OR_GREATER
using System.Text.Unicode;
#endif

namespace DnsClient
{
    internal class DnsRecordFactory
    {
        private readonly DnsDatagramReader _reader;

        public DnsRecordFactory(DnsDatagramReader reader)
        {
            _reader = reader ?? throw new ArgumentNullException(nameof(reader));
        }

        /*
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         * */

        public ResourceRecordInfo ReadRecordInfo()
        {
            return new ResourceRecordInfo(
                _reader.ReadQuestionQueryString(),                      // name
                (ResourceRecordType)_reader.ReadUInt16NetworkOrder(),   // type
                (QueryClass)_reader.ReadUInt16NetworkOrder(),           // class
                (int)_reader.ReadUInt32NetworkOrder(),                  // TTL - 32bit!!
                _reader.ReadUInt16NetworkOrder());                      // RDLength
        }

        public DnsResourceRecord GetRecord(ResourceRecordInfo info)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var oldIndex = _reader.Index;
            DnsResourceRecord result;

            switch (info.RecordType)
            {
                case ResourceRecordType.A:
                    result = new ARecord(info, _reader.ReadIPAddress());
                    break;

                case ResourceRecordType.NS:
                    result = new NsRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.CNAME:
                    result = new CNameRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.SOA:
                    result = ResolveSoaRecord(info);
                    break;

                case ResourceRecordType.MB:
                    result = new MbRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.MG:
                    result = new MgRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.MR:
                    result = new MrRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.NULL:
                    result = new NullRecord(info, _reader.ReadBytes(info.RawDataLength).ToArray());
                    break;

                case ResourceRecordType.WKS:
                    result = ResolveWksRecord(info);
                    break;

                case ResourceRecordType.PTR:
                    result = new PtrRecord(info, _reader.ReadDnsName());
                    break;

                case ResourceRecordType.HINFO:
                    result = new HInfoRecord(info, _reader.ReadStringWithLengthPrefix(), _reader.ReadStringWithLengthPrefix());
                    break;

                case ResourceRecordType.MINFO:
                    result = new MInfoRecord(info, _reader.ReadDnsName(), _reader.ReadDnsName());
                    break;

                case ResourceRecordType.MX:
                    result = ResolveMXRecord(info);
                    break;

                case ResourceRecordType.TXT:
                    result = ResolveTxtRecord(info);
                    break;

                case ResourceRecordType.RP:
                    result = new RpRecord(info, _reader.ReadDnsName(), _reader.ReadDnsName());
                    break;

                case ResourceRecordType.AFSDB: // 18
                    result = new AfsDbRecord(info, (AfsType)_reader.ReadUInt16NetworkOrder(), _reader.ReadDnsName());
                    break;

                case ResourceRecordType.AAAA: // 28
                    result = new AaaaRecord(info, _reader.ReadIPv6Address());
                    break;

                case ResourceRecordType.SRV: // 33
                    result = ResolveSrvRecord(info);
                    break;

                case ResourceRecordType.NAPTR:
                    result = ResolveNaptrRecord(info);
                    break;

                case ResourceRecordType.CERT: // 37
                    result = ResolveCertRecord(info);
                    break;

                case ResourceRecordType.OPT: // 41
                    result = ResolveOptRecord(info);
                    break;

                case ResourceRecordType.DS: // 43
                    result = ResolveDsRecord(info);
                    break;

                case ResourceRecordType.SSHFP: // 44
                    result = ResolveSshfpRecord(info);
                    break;

                case ResourceRecordType.RRSIG: // 46
                    result = ResolveRRSigRecord(info);
                    break;

                case ResourceRecordType.NSEC: // 47
                    result = ResolveNSecRecord(info);
                    break;

                case ResourceRecordType.DNSKEY: // 48
                    result = ResolveDnsKeyRecord(info);
                    break;

                case ResourceRecordType.NSEC3: // 50
                    result = ResolveNSec3Record(info);
                    break;

                case ResourceRecordType.NSEC3PARAM: // 51
                    result = ResolveNSec3ParamRecord(info);
                    break;

                case ResourceRecordType.TLSA: // 52
                    result = ResolveTlsaRecord(info);
                    break;

                case ResourceRecordType.SPF: // 99
                    result = ResolveTxtRecord(info);
                    break;

                case ResourceRecordType.URI: // 256
                    result = ResolveUriRecord(info);
                    break;

                case ResourceRecordType.CAA: // 257
                    result = ResolveCaaRecord(info);
                    break;

                default:
                    result = new UnknownRecord(info, _reader.ReadBytes(info.RawDataLength).ToArray());
                    break;
            }

            // sanity check
            _reader.SanitizeResult(oldIndex + info.RawDataLength, info.RawDataLength);

            return result;
        }

        private SoaRecord ResolveSoaRecord(ResourceRecordInfo info)
        {
            var mName = _reader.ReadDnsName();
            var rName = _reader.ReadDnsName();
            var serial = _reader.ReadUInt32NetworkOrder();
            var refresh = _reader.ReadUInt32NetworkOrder();
            var retry = _reader.ReadUInt32NetworkOrder();
            var expire = _reader.ReadUInt32NetworkOrder();
            var minimum = _reader.ReadUInt32NetworkOrder();

            return new SoaRecord(info, mName, rName, serial, refresh, retry, expire, minimum);
        }

        private WksRecord ResolveWksRecord(ResourceRecordInfo info)
        {
            var address = _reader.ReadIPAddress();
            var protocol = _reader.ReadByte();
            var bitmap = _reader.ReadBytes(info.RawDataLength - 5);

            return new WksRecord(info, address, protocol, bitmap.ToArray());
        }

        private MxRecord ResolveMXRecord(ResourceRecordInfo info)
        {
            var preference = _reader.ReadUInt16NetworkOrder();
            var domain = _reader.ReadDnsName();

            return new MxRecord(info, preference, domain);
        }

        private TxtRecord ResolveTxtRecord(ResourceRecordInfo info)
        {
            int pos = _reader.Index;

            var values = new List<string>();
            var utf8Values = new List<string>();
            while ((_reader.Index - pos) < info.RawDataLength)
            {
                var length = _reader.ReadByte();
                var bytes = _reader.ReadBytes(length);
                var utf = DnsDatagramReader.ReadUTF8String(bytes);
                var escaped = DnsDatagramReader.ParseString(bytes.ToArray());
                values.Add(escaped);
                utf8Values.Add(utf);
            }

            return new TxtRecord(info, values.ToArray(), utf8Values.ToArray());
        }

        private SrvRecord ResolveSrvRecord(ResourceRecordInfo info)
        {
            var priority = _reader.ReadUInt16NetworkOrder();
            var weight = _reader.ReadUInt16NetworkOrder();
            var port = _reader.ReadUInt16NetworkOrder();
            var target = _reader.ReadDnsName();

            return new SrvRecord(info, priority, weight, port, target);
        }

        private NAPtrRecord ResolveNaptrRecord(ResourceRecordInfo info)
        {
            var order = _reader.ReadUInt16NetworkOrder();
            var preference = _reader.ReadUInt16NetworkOrder();
            var flags = _reader.ReadStringWithLengthPrefix();
            var services = _reader.ReadStringWithLengthPrefix();
            var regexp = _reader.ReadStringWithLengthPrefix();
            var replacement = _reader.ReadDnsName();

            return new NAPtrRecord(info, order, preference, flags, services, regexp, replacement);
        }

        private CertRecord ResolveCertRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var certType = _reader.ReadUInt16NetworkOrder();
            var keyTag = _reader.ReadUInt16NetworkOrder();
            var algorithm = _reader.ReadByte();
            var publicKey = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();

            return new CertRecord(info, certType, keyTag, algorithm, publicKey);
        }

        private OptRecord ResolveOptRecord(ResourceRecordInfo info)
        {
            // Consume bytes in case the OPT record has any.
            // now being kept for back-compat
            var bytes = _reader.ReadBytes_WithoutAdvancing(info.RawDataLength).ToArray();
            
            List<OptBaseOption> options = new List<OptBaseOption>();

            int pos = _reader.Index;
            while ((_reader.Index - pos) < info.RawDataLength)
            {
                ushort code = _reader.ReadUInt16NetworkOrder();
                ushort length = _reader.ReadUInt16NetworkOrder();

                if (Enum.IsDefined(typeof(OptOption), (int)code))
                {
                    var validOptOption = (OptOption)code;
                    switch (validOptOption)
                    {
                        case OptOption.EDE:
                            var newEde = new EDEOption();
                            newEde.Length = length;
                            newEde.RawInfoCode = _reader.ReadUInt16NetworkOrder();
                            if (Enum.IsDefined(typeof(EDECodes), (int)newEde.RawInfoCode))
                                newEde.InfoCode = (EDECodes)newEde.RawInfoCode;
                            else
                                newEde.InfoCode = EDECodes.Unknown;
                            if (length - 2 > 0) // minus 2 to account for InfoCode
                                newEde.ExtraText = _reader.ReadString(length - 2);
                            options.Add(newEde);
                            break;
                        case OptOption.NSID:
                            var newNSID = new NSIDOption();
                            newNSID.Length = length;
                            if (length != 0)
                            {
                                newNSID.Data = _reader.ReadBytes(length).ToArray();

                                if (newNSID.Data.Any())
                                {
#if NET8_0_OR_GREATER
                                    if (Utf8.IsValid(newNSID.Data))
                                        newNSID.UTF8Data = Encoding.UTF8.GetString(newNSID.Data);
#else
                                    // wish we had an easier way of doing this without falling back to handling exceptions. It doesn't seem very many DNS Servers respond with anything but UTF8/ASCII strings though in the wild, none of the very popular resolvers at least
                                    // Create an encoder/decoder with exception fallback
                                    var encoding = new UTF8Encoding(false, true);

                                    try
                                    {
                                        // Attempt to decode the byte array to a string
                                        newNSID.UTF8Data = encoding.GetString(newNSID.Data);
                                    }
                                    catch (ArgumentException) // catches DecoderFallBackException too
                                    {
                                    }
#endif
                                }
                            }
                            else
                            {
                                newNSID.Data = Array.Empty<byte>();
                            }

                            options.Add(newNSID);
                            break;

                    }
                }
                else
                {
                    // not a supported option type, we need to advance past it
                    _reader.Advance(length);
                }
            }



            return new OptRecord((int)info.RecordClass, ttlFlag: info.InitialTimeToLive, length: info.RawDataLength, data: bytes, options.ToArray());
        }

        private DsRecord ResolveDsRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var keyTag = _reader.ReadUInt16NetworkOrder();
            var algorithm = _reader.ReadByte();
            var digestType = _reader.ReadByte();
            var digest = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new DsRecord(info, keyTag, algorithm, digestType, digest);
        }

        private SshfpRecord ResolveSshfpRecord(ResourceRecordInfo info)
        {
            var algorithm = (SshfpAlgorithm)_reader.ReadByte();
            var fingerprintType = (SshfpFingerprintType)_reader.ReadByte();
            var fingerprint = _reader.ReadBytes(info.RawDataLength - 2).ToArray();
            var fingerprintHexString = string.Join(string.Empty, fingerprint.Select(b => b.ToString("X2")));
            return new SshfpRecord(info, algorithm, fingerprintType, fingerprintHexString);
        }

        private RRSigRecord ResolveRRSigRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var type = _reader.ReadUInt16NetworkOrder();
            var algorithmNumber = _reader.ReadByte();
            var labels = _reader.ReadByte();
            var originalTtl = _reader.ReadUInt32NetworkOrder();
            var signatureExpiration = _reader.ReadUInt32NetworkOrder();
            var signatureInception = _reader.ReadUInt32NetworkOrder();
            var keyTag = _reader.ReadUInt16NetworkOrder();
            var signersName = _reader.ReadDnsName();
            var signature = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new RRSigRecord(info, type, algorithmNumber, labels, originalTtl, signatureExpiration, signatureInception, keyTag, signersName, signature);
        }

        private NSecRecord ResolveNSecRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var nextName = _reader.ReadDnsName();
            var bitMaps = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new NSecRecord(info, nextName, bitMaps);
        }

        private NSec3Record ResolveNSec3Record(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var hashAlgorithm = _reader.ReadByte();
            var flags = _reader.ReadByte();
            var iterations = _reader.ReadUInt16NetworkOrder();
            var saltLength = _reader.ReadByte();
            var salt = _reader.ReadBytes(saltLength).ToArray();
            var nextOwnerLength = _reader.ReadByte();
            var nextOwnersName = _reader.ReadBytes(nextOwnerLength).ToArray();
            var bitMaps = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new NSec3Record(info, hashAlgorithm, flags, iterations, salt, nextOwnersName, bitMaps);
        }

        private NSec3ParamRecord ResolveNSec3ParamRecord(ResourceRecordInfo info)
        {
            var hashAlgorithm = _reader.ReadByte();
            var flags = _reader.ReadByte();
            var iterations = _reader.ReadUInt16NetworkOrder();
            var saltLength = _reader.ReadByte();
            var salt = _reader.ReadBytes(saltLength).ToArray();
            return new NSec3ParamRecord(info, hashAlgorithm, flags, iterations, salt);
        }

        private DnsKeyRecord ResolveDnsKeyRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            int flags = _reader.ReadUInt16NetworkOrder();
            var protocol = _reader.ReadByte();
            var algorithm = _reader.ReadByte();
            var publicKey = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new DnsKeyRecord(info, flags, protocol, algorithm, publicKey);
        }

        private TlsaRecord ResolveTlsaRecord(ResourceRecordInfo info)
        {
            var startIndex = _reader.Index;
            var certificateUsage = _reader.ReadByte();
            var selector = _reader.ReadByte();
            var matchingType = _reader.ReadByte();
            var certificateAssociationData = _reader.ReadBytesToEnd(startIndex, info.RawDataLength).ToArray();
            return new TlsaRecord(info, certificateUsage, selector, matchingType, certificateAssociationData);
        }

        private UriRecord ResolveUriRecord(ResourceRecordInfo info)
        {
            var prio = _reader.ReadUInt16NetworkOrder();
            var weight = _reader.ReadUInt16NetworkOrder();
            var target = _reader.ReadString(info.RawDataLength - 4);
            return new UriRecord(info, prio, weight, target);
        }

        private CaaRecord ResolveCaaRecord(ResourceRecordInfo info)
        {
            var flag = _reader.ReadByte();
            var tag = _reader.ReadStringWithLengthPrefix();
            var stringValue = DnsDatagramReader.ParseString(_reader.ReadBytes(info.RawDataLength - 2 - tag.Length).ToArray());
            return new CaaRecord(info, flag, tag, stringValue);
        }
    }
}
