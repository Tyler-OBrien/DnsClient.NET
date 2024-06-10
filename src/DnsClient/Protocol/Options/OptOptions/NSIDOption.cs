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
    public class NSIDOption : OptBaseOption
    {
        public override OptOption Code => OptOption.NSID;

        public byte[] Data { get; set; }

        public string UTF8Data { get; set; }


        /// <inheritdoc />
        public override string ToString()
        {
            return RecordToString();
        }
        public override string RecordToString()
        {
            return
                $"{this.Code.ToString()}: {BitConverter.ToString(Data).Replace("-", " ")} {(String.IsNullOrWhiteSpace(UTF8Data) == false ? $"(\"{UTF8Data}\")" : string.Empty)}";
        }
    }
}
