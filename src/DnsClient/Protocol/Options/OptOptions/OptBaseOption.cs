// Copyright 2024 Michael Conrad.
// Licensed under the Apache License, Version 2.0.
// See LICENSE file for details.

namespace DnsClient.Protocol.Options.OptOptions
{
    /* https://tools.ietf.org/html/rfc6891#section-4.3
    6.1.2.  Wire Format
     *                    OPT RR Format
       
       
       The variable part of an OPT RR may contain zero or more options in
       the RDATA.  Each option MUST be treated as a bit field.  Each option
       is encoded as:
       
                      +0 (MSB)                            +1 (LSB)
           +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        0: |                          OPTION-CODE                          |
           +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        2: |                         OPTION-LENGTH                         |
           +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        4: |                                                               |
           /                          OPTION-DATA                          /
           /                                                               /
           +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       
       OPTION-CODE
          Assigned by the Expert Review process as defined by the DNSEXT
          working group and the IESG.
       
       OPTION-LENGTH
          Size (in octets) of OPTION-DATA.
       
       OPTION-DATA
          Varies per OPTION-CODE.  MUST be treated as a bit field.
       
       The order of appearance of option tuples is not defined.  If one
       option modifies the behaviour of another or multiple options are
       related to one another in some way, they have the same effect
       regardless of ordering in the RDATA wire encoding.
       
       Any OPTION-CODE values not understood by a responder or requestor
       MUST be ignored.  Specifications of such options might wish to
       include some kind of signaled acknowledgement.  For example, an
       option specification might say that if a responder sees and supports
       option XYZ, it MUST include option XYZ in its response.
       
     */
    /// <summary>
    /// This type represents an Option Code
    /// </summary>
    public abstract class OptBaseOption
    {
        /// <summary>
        /// Option Code for this Option
        /// </summary>
        public abstract OptOption Code { get; }

        /// <summary>
        /// Length in Bytes for this Option's Data
        /// </summary>
        public int Length { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            return RecordToString();
        }


        /// <summary>
        /// Returns a string representation of the record.
        /// </summary>
        /// <returns>A string representing this record.</returns>
        public abstract string RecordToString();
    }
}
