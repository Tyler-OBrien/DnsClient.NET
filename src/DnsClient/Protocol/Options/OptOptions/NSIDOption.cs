// Copyright 2024 Michael Conrad.
// Licensed under the Apache License, Version 2.0.
// See LICENSE file for details.

using System;

namespace DnsClient.Protocol.Options.OptOptions
{
    /* https://datatracker.ietf.org/doc/rfc5001/
     *2.3.  The NSID Option

       The OPTION-CODE for the NSID option is 3.

       The OPTION-DATA for the NSID option is an opaque byte string, the
       semantics of which are deliberately left outside the protocol.  See
       Section 3.1 for discussion.
     */
    /// <summary>
    /// A <see cref="OptBaseOption"/> representing the DNS Name Server Identifier  (NSID) Option
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5001.html">RFC 5001</seealso>
    /// </summary>
    public class NSIDOption : OptBaseOption
    {
        /// <inheritdoc />
        public override OptOption Code => OptOption.NSID;

        /// <summary>
        /// Raw Data in NSID Option-Data
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// If NSID Option-Data was a valid UTF8 String, UTF8Data will contain the parsed string. Otherwise, null.
        /// </summary>
        public string UTF8Data { get; set; }


        /// <inheritdoc />
        public override string ToString()
        {
            return RecordToString();
        }
        /// <inheritdoc />
        public override string RecordToString()
        {
            return
                $"{Code}: {BitConverter.ToString(Data).Replace("-", " ")} {(string.IsNullOrWhiteSpace(UTF8Data) == false ? $"(\"{UTF8Data}\")" : string.Empty)}";
        }
    }
}
