// Copyright 2024 Michael Conrad.
// Licensed under the Apache License, Version 2.0.
// See LICENSE file for details.

namespace DnsClient.Protocol.Options.OptOptions
{
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    // COOKIE and ECS (Client Subnet) would be interesting to support. Cookie would need some modifications to ignore invalid/spoofed packets, and ECS would need some modifications to work with cache.

    /// <summary>
    /// Supported Option Codes
    /// </summary>
    public enum OptOption
    {

        /// <summary>
        /// Nameserver Identifier
        /// </summary>
        /// <seealso href="https://www.rfc-editor.org/rfc/rfc5001.html">RFC 5001</seealso>
        /// <seealso cref="NSIDOption"/>
        NSID = 3,


        /// <summary>
        /// Extended DNS Error
        /// </summary>
        /// <seealso href="https://www.iana.org/go/rfc8914">RFC 8914</seealso>
        /// <seealso cref="EDEOption"/>
        EDE = 15,
    }
}
