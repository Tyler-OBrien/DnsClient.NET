﻿using System.Linq;
using System.Net;
using DnsClient2.Protocol;
using DnsClient2.Protocol.Record;
using Xunit;

namespace DnsClient2.Test
{
    public class DnsMessageHandlerTest
    {
        [Fact]
        public void DnsRecordFactory_ResolveARecord()
        {
            var header = new DnsResponseHeader(42, 256, 0, 1, 0, 0);
            var response = new DnsResponseMessage(header);

            var info = new ResourceRecordInfo("query", 1, 1, 100, 4);
            var ip = IPAddress.Parse("123.45.67.9");
            var answer = new ARecord(info, ip);
            response.AddAnswer(answer);

            var answerBytes = ip.GetAddressBytes();

            var raw = GetResponseBytes(response, answerBytes);

            var handle = new DnsUdpMessageHandler();
            var result = handle.GetResponseMessage(raw);

            Assert.Equal(result.Answers.Count, 1);
            var resultAnswer = result.Answers.OfType<ARecord>().First();
            Assert.Equal(resultAnswer.Address.ToString(), ip.ToString());
            Assert.Equal(resultAnswer.QueryName, "query.");
            Assert.Equal(resultAnswer.RawDataLength, 4);
            Assert.Equal(resultAnswer.RecordClass, 1);
            Assert.Equal(resultAnswer.RecordType, 1);
            Assert.True(resultAnswer.TimeToLive == 100);
            Assert.True(result.Header.Id == 42);
            Assert.True(result.Header.AnswerCount == 1);
        }

        private static byte[] GetResponseBytes(DnsResponseMessage message, byte[] answerData)
        {
            var writer = new DnsDatagramWriter(12);
            writer.SetUInt16Network((ushort)message.Header.Id);
            writer.SetUInt16Network((ushort)message.Header.HeaderFlags);
            // lets iterate answers only, makse it easier
            //writer.SetUInt16Network((ushort)message.Header.QuestionCount);
            writer.SetUInt16Network(0);
            writer.SetUInt16Network(1);
            //writer.SetUInt16Network((ushort)message.Header.NameServerCount);
            writer.SetUInt16Network(0);
            //writer.SetUInt16Network((ushort)message.Header.AdditionalCount);
            writer.SetUInt16Network(0);

            var answer = message.Answers.First();
            var q = new DnsName(answer.QueryName).AsBytes();
            writer.Extend(q.Length);    // the following query->length
            writer.SetBytes(q, q.Length);
            writer.Extend(10);  // the following 4x ushort
            writer.SetUInt16Network(answer.RecordType);
            writer.SetUInt16Network(answer.RecordClass);
            writer.SetUInt32Network(answer.TimeToLive);
            writer.SetUInt16Network((ushort)answerData.Length);

            writer.Extend(answerData.Length);   // the following data->length
            writer.SetBytes(answerData, answerData.Length);

            return writer.Data;
        }
    }
}