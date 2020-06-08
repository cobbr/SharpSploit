// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Generic;

using SharpSploit.Generic;

namespace SharpSploit.Pivoting
{
    /// <summary>
    /// ReversePortForwarding is a class that allows the addition and removal of Reverse Port Forwards.
    /// </summary>
    public class ReversePortForwarding
    {
        public class ReversePortForward
        {
            public IPAddress BindAddress { get; set; }
            public int BindPort { get; set; }
            public IPAddress ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
        }

        private static List<ReversePortForward> _reversePortForwards = new List<ReversePortForward>();
        private static Dictionary<int, Socket> _boundSockets = new Dictionary<int, Socket>();


        /// <summary>
        /// Creates a new Reverse Port Forward.
        /// </summary>
        /// <param name="BindPort">The port to bind on the local system.</param>
        /// <param name="ForwardAddress">The IP Address or DNS name to forward traffic to.</param>
        /// <param name="ForwardPort">The port to forward traffic to.</param>
        /// <returns>Bool.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool CreateReversePortForward(int BindPort, string ForwardAddress, int ForwardPort)
        {
            // If ForwardHost is not a valid IP, try to resolve it as DNS.
            if (!IPAddress.TryParse(ForwardAddress, out IPAddress forwardAddress))
            {
                try
                {
                    var ipHostInfo = Dns.GetHostEntry(ForwardAddress);
                    forwardAddress = ipHostInfo.AddressList[0];
                }
                catch
                {
                    return false;
                }
            }
            return CreateReversePortForward(BindPort, forwardAddress, ForwardPort);
        }

        /// <summary>
        /// Creates a new Reverse Port Forward.
        /// </summary>
        /// <param name="BindPort">The port to bind on the local system.</param>
        /// <param name="ForwardAddress">The IP Address or DNS name to forward traffic to.</param>
        /// <param name="ForwardPort">The port to forward traffic to.</param>
        /// <returns>Bool.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool CreateReversePortForward(int BindPort, IPAddress ForwardAddress, int ForwardPort)
        {
            // Check if bindPort is not already bound.
            if (_boundSockets.ContainsKey(BindPort))
            {
                return false;
            }

            // Bind the sockets
            Socket boundSocket = BindSocket(IPAddress.Any, BindPort);
            if (boundSocket == null)
            {
                return false;
            }

            ReversePortForward newReversePortForward = new ReversePortForward
            {
                BindAddress = IPAddress.Any,
                BindPort = BindPort,
                ForwardAddress = ForwardAddress,
                ForwardPort = ForwardPort
            };

            // Add to Lists
            _reversePortForwards.Add(newReversePortForward);
            _boundSockets[BindPort] = boundSocket;

            // Kick off client sockets in new thread.
            new Thread(() => CreateClientSocketThread(boundSocket, ForwardAddress, ForwardPort)).Start();
            return true;
        }

        /// <summary>
        /// Deletes an active Reverse Port Forward.
        /// </summary>
        /// <param name="BindPort">The bind port of the Reverse Port Forward.</param>
        /// <returns>Bool.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool DeleteReversePortForward(int BindPort)
        {
            if (!_boundSockets.TryGetValue(BindPort, out Socket socket))
            {
                return false;
            }

            try
            {
                try { socket.Shutdown(SocketShutdown.Both); }
                catch (SocketException) { }
                socket.Close();

                _boundSockets.Remove(BindPort);

                ReversePortForward reversePortForward = _reversePortForwards.FirstOrDefault(r => r.BindPort.Equals(BindPort));
                _reversePortForwards.Remove(reversePortForward);

                return true;
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Gets a list of active Reverse Port Forwards.
        /// </summary>
        /// <returns>A SharpSploitResultList of ReversePortFwdResult</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static SharpSploitResultList<ReversePortFwdResult> GetReversePortForwards()
        {
            SharpSploitResultList<ReversePortFwdResult> reversePortForwards = new SharpSploitResultList<ReversePortFwdResult>();

            foreach (ReversePortForward rportfwd in _reversePortForwards)
            {
                reversePortForwards.Add(new ReversePortFwdResult
                {
                    BindAddresses = rportfwd.BindAddress.ToString(),
                    BindPort = rportfwd.BindPort,
                    ForwardAddress = rportfwd.ForwardAddress.ToString(),
                    ForwardPort = rportfwd.ForwardPort
                });
            }
            return reversePortForwards;
        }

        /// <summary>
        /// Delete all active Reverse Port Forwards.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static void FlushReversePortFowards()
        {
            try
            {
                foreach (Socket socket in _boundSockets.Values)
                {
                    try { socket.Shutdown(SocketShutdown.Both); }
                    catch (SocketException) { }
                    socket.Close();
                }

                _boundSockets.Clear();
                _reversePortForwards.Clear();
            }
            catch { }
        }

        private static Socket BindSocket(IPAddress BindAddress, int BindPort)
        {
            IPEndPoint localEP = new IPEndPoint(BindAddress, BindPort);
            Socket socket = new Socket(BindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(localEP);
                socket.Listen(10);
            }
            catch (SocketException) { }
            return socket;
        }

        private static void CreateClientSocketThread(Socket BoundSocket, IPAddress ForwardAddress, int ForwardPort)
        {
            IPEndPoint remoteEP = new IPEndPoint(ForwardAddress, ForwardPort);

            while (true)
            {
                byte[] boundBuffer = new byte[1024];
                byte[] clientBuffer = new byte[1048576];

                try
                {
                    // Receive data on bound socket
                    Socket handler = BoundSocket.Accept();
                    handler.Receive(boundBuffer);

                    // Create new client socket
                    using (Socket clientSocket = new Socket(ForwardAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                    {
                        try
                        {
                            clientSocket.Connect(remoteEP);
                            clientSocket.Send(boundBuffer);
                            clientSocket.Receive(clientBuffer);
                        }
                        catch (SocketException) { }
                    }
                    handler.Send(clientBuffer);
                }
                catch { }
            }
        }

        public sealed class ReversePortFwdResult : SharpSploitResult
        {
            public string BindAddresses { get; set; }
            public int BindPort { get; set; }
            public string ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty> {
                        new SharpSploitResultProperty { Name = "BindAddresses", Value = this.BindAddresses },
                        new SharpSploitResultProperty { Name = "BindPort", Value = this.BindPort },
                        new SharpSploitResultProperty { Name = "ForwardAddress", Value = this.ForwardAddress },
                        new SharpSploitResultProperty { Name = "ForwardPort", Value = this.ForwardPort }
                    };
                }
            }
        }
    }
}