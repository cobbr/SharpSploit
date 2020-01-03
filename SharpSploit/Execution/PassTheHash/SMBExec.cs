using SharpSploit.Misc;
using System;
using System.Collections.Specialized;
using System.Linq;

namespace SharpSploit.Execution
{
    public class SMBExec
    {
        /// <summary>
        /// SMBExec contains all of the functions used to manually create SMB Packet Structures for Pass the Hash attacks.
        /// </summary>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        
        #region SMBv1
        public static OrderedDictionary NetBIOSSessionService(int packet_header_length, int packet_data_length)
        {
            byte[] packet_netbios_session_service_length = BitConverter.GetBytes(packet_header_length + packet_data_length);
            packet_netbios_session_service_length = new byte[] { packet_netbios_session_service_length[2], packet_netbios_session_service_length[1], packet_netbios_session_service_length[0] };

            OrderedDictionary packet_NetBIOSSessionService = new OrderedDictionary();
            packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type", new byte[] { 0x00 });
            packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length", packet_netbios_session_service_length);

            return packet_NetBIOSSessionService;
        }
        public static OrderedDictionary SMBHeader(byte[] packet_command, byte[] packet_flags, byte[] packet_flags2, byte[] packet_tree_ID, byte[] packet_process_ID, byte[] packet_user_ID)
        {
            byte[] ProcessID = new byte[2] { packet_process_ID[0], packet_process_ID[1] };
            OrderedDictionary packet_SMBHeader = new OrderedDictionary();
            packet_SMBHeader.Add("SMBHeader_Protocol", new byte[] { 0xff, 0x53, 0x4d, 0x42 });
            packet_SMBHeader.Add("SMBHeader_Command", packet_command);
            packet_SMBHeader.Add("SMBHeader_ErrorClass", new byte[] { 0x00 });
            packet_SMBHeader.Add("SMBHeader_Reserved", new byte[] { 0x00 });
            packet_SMBHeader.Add("SMBHeader_ErrorCode", new byte[] { 0x00, 0x00 });
            packet_SMBHeader.Add("SMBHeader_Flags", packet_flags);
            packet_SMBHeader.Add("SMBHeader_Flags2", packet_flags2);
            packet_SMBHeader.Add("SMBHeader_ProcessIDHigh", new byte[] { 0x00, 0x00 });
            packet_SMBHeader.Add("SMBHeader_Signature", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMBHeader.Add("SMBHeader_Reserved2", new byte[] { 0x00, 0x00 });
            packet_SMBHeader.Add("SMBHeader_TreeID", packet_tree_ID);
            packet_SMBHeader.Add("SMBHeader_ProcessID", ProcessID);
            packet_SMBHeader.Add("SMBHeader_UserID", packet_user_ID);
            packet_SMBHeader.Add("SMBHeader_MultiplexID", new byte[] { 0x00, 0x00 });
            return packet_SMBHeader;
        }
        public static OrderedDictionary SMBNegotiateProtocolRequest(bool ForceSMB1)
        {
            byte[] packet_byte_count;
            if (ForceSMB1)
            {
                packet_byte_count = new byte[] { 0x0c, 0x00 };
            }
            else
            {
                packet_byte_count = new byte[] { 0x22, 0x00 };
            }
            //https://msdn.microsoft.com/en-us/library/ee441572.aspx
            OrderedDictionary packet_SMBNegotiateProtocolRequest = new OrderedDictionary();
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount", new byte[] { 0x00 });
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount", packet_byte_count);
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat", new byte[] { 0x02 });
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name", new byte[] { 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00 });

            if (!ForceSMB1)
            {
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2", new byte[] { 0x02 });
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2", new byte[] { 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00 });
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3", new byte[] { 0x02 });
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3", new byte[] { 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00 });
            }

            return packet_SMBNegotiateProtocolRequest;
        }
        public static OrderedDictionary SMBSessionSetupAndXRequest(byte[] packet_security_blob)
        {
            //https://msdn.microsoft.com/en-us/library/ee441849.aspx


            byte[] packet_byte_count = BitConverter.GetBytes(packet_security_blob.Length);
            byte[] packet_byte_count2 = { packet_byte_count[0], packet_byte_count[1] };
            byte[] packet_security_blob_length = BitConverter.GetBytes(packet_security_blob.Length + 5);
            byte[] packet_security_blob_length2 = { packet_security_blob_length[0], packet_security_blob_length[1] };

            OrderedDictionary packet_SMBSessionSetupAndXRequest = new OrderedDictionary();
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_WordCount", new byte[] { 0x0c });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxBuffer", new byte[] { 0xff, 0xff });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxMpxCount", new byte[] { 0x02, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_VCNumber", new byte[] { 0x01, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SessionKey", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlobLength", packet_byte_count2);
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Capabilities", new byte[] { 0x44, 0x00, 0x00, 0x80 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_ByteCount", packet_security_blob_length2);
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlob", packet_security_blob);
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeOS", new byte[] { 0x00, 0x00, 0x00 });
            packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeLANManage", new byte[] { 0x00, 0x00 });

            return packet_SMBSessionSetupAndXRequest;
        }
        public static OrderedDictionary SMBTreeConnectAndXRequest(byte[] packet_path)
        {
            byte[] packet_path_length = BitConverter.GetBytes(packet_path.Length + 7);
            packet_path_length = new byte[] { packet_path_length[0], packet_path_length[1] };

            OrderedDictionary packet_SMBTreeConnectAndXRequest = new OrderedDictionary();
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_WordCount", new byte[] { 0x04 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Flags", new byte[] { 0x00, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_PasswordLength", new byte[] { 0x01, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_ByteCount", packet_path_length);
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Password", new byte[] { 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Tree", packet_path);
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Service", new byte[] { 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00 });

            return packet_SMBTreeConnectAndXRequest;
        }
        public static OrderedDictionary SMBNTCreateAndXRequest(byte[] packet_named_pipe)
        {
            byte[] packet_named_pipe_length = BitConverter.GetBytes(packet_named_pipe.Length);
            byte[] packet_named_pipe_length2 = { packet_named_pipe_length[0], packet_named_pipe_length[1] };
            byte[] packet_file_name_length = BitConverter.GetBytes(packet_named_pipe.Length - 1);
            byte[] packet_file_name_length2 = { packet_file_name_length[0], packet_file_name_length[1] };

            OrderedDictionary packet_SMBNTCreateAndXRequest = new OrderedDictionary();
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_WordCount", new byte[] { 0x18 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved2", new byte[] { 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileNameLen", packet_file_name_length2);
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateFlags", new byte[] { 0x16, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_RootFID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AccessMask", new byte[] { 0x00, 0x00, 0x00, 0x02 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AllocationSize", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileAttributes", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ShareAccess", new byte[] { 0x07, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Disposition", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateOptions", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Impersonation", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_SecurityFlags", new byte[] { 0x00 });
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ByteCount", packet_named_pipe_length2);
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Filename", packet_named_pipe);

            return packet_SMBNTCreateAndXRequest;
        }
        public static OrderedDictionary SMBReadAndXRequest(byte[] SMB_FID)
        {

            if (SMB_FID == null)
            {
                SMB_FID = new byte[] { 0x00, 0x40 };
            }
            OrderedDictionary packet_SMBReadAndXRequest = new OrderedDictionary();
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_WordCount", new byte[] { 0x0a });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_FID", SMB_FID);
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MaxCountLow", new byte[] { 0x58, 0x02 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MinCount", new byte[] { 0x58, 0x02 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Unknown", new byte[] { 0xff, 0xff, 0xff, 0xff });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Remaining", new byte[] { 0x00, 0x00 });
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_ByteCount", new byte[] { 0x00, 0x00 });

            return packet_SMBReadAndXRequest;
        }
        public static OrderedDictionary SMBWriteAndXRequest(byte[] packet_file_ID, int packet_RPC_length)
        {
            byte[] packet_write_length = BitConverter.GetBytes(packet_RPC_length);
            packet_write_length = new byte[] { packet_write_length[0], packet_write_length[1] };

            OrderedDictionary packet_SMBWriteAndXRequest = new OrderedDictionary();
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WordCount", new byte[] { 0x0e });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_FID", packet_file_ID);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Offset", new byte[] { 0xea, 0x03, 0x00, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved2", new byte[] { 0xff, 0xff, 0xff, 0xff });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WriteMode", new byte[] { 0x08, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Remaining", packet_write_length);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthHigh", new byte[] { 0x00, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthLow", packet_write_length);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataOffset", new byte[] { 0x3f, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_HighOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_ByteCount", packet_write_length);

            return packet_SMBWriteAndXRequest;
        }
        public static OrderedDictionary SMBCloseRequest(byte[] packet_file_ID)
        {

            OrderedDictionary packet_SMBCloseRequest = new OrderedDictionary();
            packet_SMBCloseRequest.Add("SMBCloseRequest_WordCount", new byte[] { 0x03 });
            packet_SMBCloseRequest.Add("SMBCloseRequest_FID", packet_file_ID);
            packet_SMBCloseRequest.Add("SMBCloseRequest_LastWrite", new byte[] { 0xff, 0xff, 0xff, 0xff });
            packet_SMBCloseRequest.Add("SMBCloseRequest_ByteCount", new byte[] { 0x00, 0x00 });

            return packet_SMBCloseRequest;
        }
        public static OrderedDictionary SMBTreeDisconnectRequest()
        {
            OrderedDictionary packet_SMBTreeDisconnectRequest = new OrderedDictionary();
            packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_WordCount", new byte[] { 0x00 });
            packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_ByteCount", new byte[] { 0x00, 0x00 });
            return packet_SMBTreeDisconnectRequest;
        }
        public static OrderedDictionary SMBLogoffAndXRequest()
        {
            OrderedDictionary packet_SMBLogoffAndXRequest = new OrderedDictionary();
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_WordCount", new byte[] { 0x02 });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXCommand", new byte[] { 0xff });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_Reserved", new byte[] { 0x00 });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXOffset", new byte[] { 0x00, 0x00 });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_ByteCount", new byte[] { 0x00, 0x00 });
            return packet_SMBLogoffAndXRequest;
        }
        #endregion
        #region SMBv2
        //public static OrderedDictionary SMB2Header(byte[] packet_command,bool SMB_signing, int packet_message_ID, byte[] process_id, byte[] packet_tree_ID, byte[] packet_session_ID)
        public static OrderedDictionary SMB2Header(byte[] packet_command, int packet_message_ID, byte[] packet_tree_ID, byte[] packet_session_ID)
        {

            byte[] message_ID = BitConverter.GetBytes(packet_message_ID);

            if (message_ID.Length == 4)
            {
                message_ID = message_ID.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                //message_ID = Utilities.CombineByteArray(message_ID, new byte[] { 0x00, 0x00, 0x00, 0x00 });
            }

            OrderedDictionary packet_SMB2Header = new OrderedDictionary();
            packet_SMB2Header.Add("SMB2Header_ProtocolID", new byte[] { 0xfe, 0x53, 0x4d, 0x42 });
            packet_SMB2Header.Add("SMB2Header_StructureSize", new byte[] { 0x40, 0x00 });
            packet_SMB2Header.Add("SMB2Header_CreditCharge", new byte[] { 0x01, 0x00 });
            packet_SMB2Header.Add("SMB2Header_ChannelSequence", new byte[] { 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_Reserved", new byte[] { 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_Command", packet_command);
            packet_SMB2Header.Add("SMB2Header_CreditRequest", new byte[] { 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_Flags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_NextCommand", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_MessageID", message_ID);
            packet_SMB2Header.Add("SMB2Header_Reserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2Header.Add("SMB2Header_TreeID", packet_tree_ID);
            packet_SMB2Header.Add("SMB2Header_SessionID", packet_session_ID);
            packet_SMB2Header.Add("SMB2Header_Signature", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

            return packet_SMB2Header;

        }
        public static OrderedDictionary SMB2NegotiateProtocolRequest()
        {
            OrderedDictionary packet_SMB2NegotiateProtocolRequest = new OrderedDictionary();
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_StructureSize", new byte[] { 0x24, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_DialectCount", new byte[] { 0x02, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_SecurityMode", new byte[] { 0x01, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved", new byte[] { 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Capabilities", new byte[] { 0x40, 0x00, 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_ClientGUID", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount", new byte[] { 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved2", new byte[] { 0x00, 0x00 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect", new byte[] { 0x02, 0x02 });
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect2", new byte[] { 0x10, 0x02 });

            return packet_SMB2NegotiateProtocolRequest;
        }
        public static OrderedDictionary SMB2SessionSetupRequest(byte[] packet_security_blob)
        {
            byte[] packet_security_blob_length = BitConverter.GetBytes(packet_security_blob.Length);
            byte[] packet_security_blob_length2 = { packet_security_blob_length[0], packet_security_blob_length[1] };

            OrderedDictionary packet_SMB2SessionSetupRequest = new OrderedDictionary();
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_StructureSize", new byte[] { 0x19, 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Flags", new byte[] { 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityMode", new byte[] { 0x01 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Capabilities", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Channel", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferOffset", new byte[] { 0x58, 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferLength", packet_security_blob_length2);
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_PreviousSessionID", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Buffer", packet_security_blob);

            return packet_SMB2SessionSetupRequest;
        }
        public static OrderedDictionary SMB2TreeConnectRequest(byte[] packet_path)
        {

            byte[] packet_path_length = BitConverter.GetBytes(packet_path.Length);
            packet_path_length = new byte[] { packet_path_length[0], packet_path_length[1] };
            OrderedDictionary packet_SMB2TreeConnectRequest = new OrderedDictionary();
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_StructureSize", new byte[] { 0x09, 0x00 });
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Reserved", new byte[] { 0x00, 0x00 });
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathOffset", new byte[] { 0x48, 0x00 });
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathLength", packet_path_length);
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Buffer", packet_path);

            return packet_SMB2TreeConnectRequest;
        }
        public static OrderedDictionary SMB2CreateRequestFile(byte[] packet_named_pipe)
        {
            byte[] packet_named_pipe_length = BitConverter.GetBytes(packet_named_pipe.Length);
            byte[] packet_named_pipe_length2 = { packet_named_pipe_length[0], packet_named_pipe_length[1] };
            OrderedDictionary packet_SMB2CreateRequestFile = new OrderedDictionary();
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_StructureSize", new byte[] { 0x39, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Flags", new byte[] { 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_RequestedOplockLevel", new byte[] { 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Impersonation", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_SMBCreateFlags", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Reserved", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_DesiredAccess", new byte[] { 0x03, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_FileAttributes", new byte[] { 0x80, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_ShareAccess", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateDisposition", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateOptions", new byte[] { 0x40, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameOffset", new byte[] { 0x78, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameLength", packet_named_pipe_length2);
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsLength", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Buffer", packet_named_pipe);

            return packet_SMB2CreateRequestFile;

        }
        public static OrderedDictionary SMB2ReadRequest(byte[] packet_file_ID)
        {
            OrderedDictionary packet_SMB2ReadRequest = new OrderedDictionary();
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_StructureSize", new byte[] { 0x31, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Padding", new byte[] { 0x50 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Flags", new byte[] { 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Length", new byte[] { 0x00, 0x00, 0x10, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_FileID", packet_file_ID);
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_MinimumCount", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Channel", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_RemainingBytes", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoOffset", new byte[] { 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoLength", new byte[] { 0x00, 0x00 });
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Buffer", new byte[] { 0x30 });

            return packet_SMB2ReadRequest;
        }
        public static OrderedDictionary SMB2WriteRequest(byte[] packet_file_ID, int packet_RPC_length)
        {


            byte[] packet_write_length = BitConverter.GetBytes(packet_RPC_length);
            OrderedDictionary packet_SMB2WriteRequest = new OrderedDictionary();
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_StructureSize", new byte[] { 0x31, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_DataOffset", new byte[] { 0x70, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Length", packet_write_length);
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_FileID", packet_file_ID);
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Channel", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_RemainingBytes", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoOffset", new byte[] { 0x00, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoLength", new byte[] { 0x00, 0x00 });
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Flags", new byte[] { 0x00, 0x00, 0x00, 0x00 });


            return packet_SMB2WriteRequest;
        }
        public static OrderedDictionary SMB2CloseRequest(byte[] packet_file_ID)
        {
            OrderedDictionary packet_SMB2CloseRequest = new OrderedDictionary();
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_StructureSize", new byte[] { 0x18, 0x00 });
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_Flags", new byte[] { 0x00, 0x00 });
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_Reserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_FileID", packet_file_ID);
            return packet_SMB2CloseRequest;
        }
        public static OrderedDictionary SMB2TreeDisconnectRequest()
        {
            OrderedDictionary packet_SMB2TreeDisconnectRequest = new OrderedDictionary();
            packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_StructureSize", new byte[] { 0x04, 0x00 });
            packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_Reserved", new byte[] { 0x00, 0x00 });
            return packet_SMB2TreeDisconnectRequest;
        }
        public static OrderedDictionary SMB2SessionLogoffRequest()
        {
            OrderedDictionary packet_SMB2SessionLogoffRequest = new OrderedDictionary();
            packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_StructureSize", new byte[] { 0x04, 0x00 });
            packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_Reserved", new byte[] { 0x00, 0x00 });
            return packet_SMB2SessionLogoffRequest;
        }
        public static OrderedDictionary NTLMSSPNegotiate(byte[] packet_negotiate_flags, byte[] packet_version)
        {
            byte[] packet_NTLMSSP_length;
            //There may be issues here, we will see.
            if (packet_version != null)
            {
                packet_NTLMSSP_length = BitConverter.GetBytes(32 + packet_version.Length);
            }
            else
            {
                packet_NTLMSSP_length = BitConverter.GetBytes(32);
            }
            byte[] packet_NTLMSSP_length2 = { packet_NTLMSSP_length[0] };

            int packet_ASN_length_1 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 32;
            byte[] packet_ASN_length_1_2 = (BitConverter.GetBytes(packet_ASN_length_1));

            int packet_ASN_length_2 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 22;
            byte[] packet_ASN_length_2_2 = (BitConverter.GetBytes(packet_ASN_length_2));

            int packet_ASN_length_3 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 20;
            byte[] packet_ASN_length_3_2 = (BitConverter.GetBytes(packet_ASN_length_3));

            int packet_ASN_length_4 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 2;
            byte[] packet_ASN_length_4_2 = BitConverter.GetBytes(packet_ASN_length_4);


            OrderedDictionary packet_NTLMSSPNegotiate = new OrderedDictionary();
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID", new byte[] { 0x60 }); // the ASN.1 key names are likely not all correct
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength", new byte[] { packet_ASN_length_1_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID", new byte[] { 0x06 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength", new byte[] { 0x06 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID", new byte[] { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID", new byte[] { 0xa0 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength", new byte[] { packet_ASN_length_2_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2", new byte[] { 0x30 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2", new byte[] { packet_ASN_length_3_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID", new byte[] { 0xa0 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength", new byte[] { 0x0e });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2", new byte[] { 0x30 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2", new byte[] { 0x0c });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3", new byte[] { 0x06 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3", new byte[] { 0x0a });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType", new byte[] { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID", new byte[] { 0xa2 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength", new byte[] { packet_ASN_length_4_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID", new byte[] { 0x04 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength", new byte[] { packet_NTLMSSP_length2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier", new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags", packet_negotiate_flags);
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

            if (packet_version != null)
            {
                packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version", packet_version);
            }

            return packet_NTLMSSPNegotiate;


        }
        public static OrderedDictionary NTLMSSPAuth(byte[] packet_NTLM_response)
        {


            byte[] packet_NTLMSSP_length = BitConverter.GetBytes(packet_NTLM_response.Length);
            packet_NTLMSSP_length = new byte[] { packet_NTLMSSP_length[1], packet_NTLMSSP_length[0] };
            byte[] packet_ASN_length_1 = BitConverter.GetBytes(packet_NTLM_response.Length + 12);
            byte[] packet_ASN_length_1_2 = { packet_ASN_length_1[1], packet_ASN_length_1[0] };
            byte[] packet_ASN_length_2 = BitConverter.GetBytes(packet_NTLM_response.Length + 8);
            byte[] packet_ASN_length_2_2 = { packet_ASN_length_2[1], packet_ASN_length_2[0] };
            byte[] packet_ASN_length_3 = BitConverter.GetBytes(packet_NTLM_response.Length + 4);
            byte[] packet_ASN_length_3_2 = { packet_ASN_length_3[1], packet_ASN_length_3[0] };



            OrderedDictionary packet_NTLMSSPAuth = new OrderedDictionary();
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID", new byte[] { 0xa1, 0x82 });
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength", packet_ASN_length_1_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2", new byte[] { 0x30, 0x82 });
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2", packet_ASN_length_2_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3", new byte[] { 0xa2, 0x82 });
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3", packet_ASN_length_3_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID", new byte[] { 0x04, 0x82 });
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength", packet_NTLMSSP_length);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse", packet_NTLM_response);

            return packet_NTLMSSPAuth;

        }
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



        //Look into to see if this can be simplified with what we already have.
        public static OrderedDictionary SCMOpenSCManagerW(byte[] packet_service, byte[] packet_service_length)
        {
            byte[] packet_write_length = BitConverter.GetBytes(packet_service.Length + 92);
            byte[] packet_frag_length = { packet_write_length[0], packet_write_length[1] };
            byte[] packet_alloc_hint = BitConverter.GetBytes(packet_service.Length + 68);
            Random r = new Random();
            byte[] packet_referent_init = new byte[2];
            r.NextBytes(packet_referent_init);
            byte[] packet_referent_ID1 = packet_referent_init.Concat(new byte[] { 0x00, 0x00 }).ToArray();
            byte[] packet_referent_init2 = new byte[2];
            r.NextBytes(packet_referent_init2);
            byte[] packet_referent_ID2 = packet_referent_init2.Concat(new byte[] { 0x00, 0x00 }).ToArray();


            OrderedDictionary packet_SCMOpenSCManagerW = new OrderedDictionary();
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ReferentID", packet_referent_ID1);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_MaxCount", packet_service_length);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ActualCount", packet_service_length);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName", packet_service);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_ReferentID", packet_referent_ID2);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameMaxCount", new byte[] { 0x0f, 0x00, 0x00, 0x00 });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameActualCount", new byte[] { 0x0f, 0x00, 0x00, 0x00 });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database", new byte[] { 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x41, 0x00, 0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x00, 0x00 });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Unknown", new byte[] { 0xbf, 0xbf });
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_AccessMask", new byte[] { 0x3f, 0x00, 0x00, 0x00 });

            return packet_SCMOpenSCManagerW;
        }
        public static OrderedDictionary SCMCreateServiceW(byte[] packet_context_handle, byte[] packet_service, byte[] packet_service_length, byte[] packet_command, byte[] packet_command_length)
        {
            Random r = new Random();
            byte[] packet_referent_init = new byte[2];
            r.NextBytes(packet_referent_init);
            byte[] nulls = { 0x00, 0x00 };
            byte[] packet_referent_ID = new byte[4];
            Buffer.BlockCopy(packet_referent_init, 0, packet_referent_ID, 0, packet_referent_init.Length);
            Buffer.BlockCopy(nulls, 0, packet_referent_ID, packet_referent_init.Length, nulls.Length);
            OrderedDictionary packet_SCMCreateServiceW = new OrderedDictionary();
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ContextHandle", packet_context_handle);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_MaxCount", packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_ActualCount", packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName", packet_service);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ReferentID", packet_referent_ID);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_MaxCount", packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ActualCount", packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName", packet_service);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_AccessMask", new byte[] { 0xff, 0x01, 0x0f, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceType", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceStartType", new byte[] { 0x03, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceErrorControl", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_MaxCount", packet_command_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_Offset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_ActualCount", packet_command_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName", packet_command);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_TagID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DependSize", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer3", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer4", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_PasswordSize", new byte[] { 0x00, 0x00, 0x00, 0x00 });

            return packet_SCMCreateServiceW;
        }
        public static OrderedDictionary SCMStartServiceW(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCMStartServiceW = new OrderedDictionary();
            packet_SCMStartServiceW.Add("SCMStartServiceW_ContextHandle", packet_context_handle);
            packet_SCMStartServiceW.Add("SCMStartServiceW_Unknown", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            return packet_SCMStartServiceW;
        }
        public static OrderedDictionary SCMDeleteServiceW(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCMDeleteServiceW = new OrderedDictionary();
            packet_SCMDeleteServiceW.Add("SCMDeleteServiceW_ContextHandle", packet_context_handle);

            return packet_SCMDeleteServiceW;
        }
        public static OrderedDictionary SCMCloseServiceHandle(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCM_CloseServiceW = new OrderedDictionary();
            packet_SCM_CloseServiceW.Add("SCMCloseServiceW_ContextHandle", packet_context_handle);

            return packet_SCM_CloseServiceW;
        }
        #endregion

    }
}
