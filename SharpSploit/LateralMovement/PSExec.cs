// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Threading;

using SharpSploit.Execution;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// PSExec is a class for executing lateral movement via the Service Control Manager.
    /// </summary>
    public class PSExec
    {
        /// <summary>
        /// Execute a process on a remote system using PSExec.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The short service name.</param>
        /// <param name="ServiceDisplayName">The friendly display name.</param>
        /// <param name="BinaryPath">The path to the Service Executable.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        public static bool ExecuteService(string ComputerName, string BinaryPath, string ServiceName = "SharpSploit", string ServiceDisplayName = "SharpSploit Service")
        {
            // We need a little wait after each step
            const int sleepTime = 1000;

            try
            {
                // Connect to the target service manager
                var hManager = OpenServiceManager(ComputerName);

                if (hManager == IntPtr.Zero)
                    return false;

                // Create the service
                Thread.Sleep(sleepTime);
                var hService = CreateService(hManager, ServiceName, ServiceDisplayName, BinaryPath);

                if (hService == IntPtr.Zero)
                    return false;

                // Start the service
                Thread.Sleep(sleepTime);
                var serviceStarted = StartService(hService);

                // If the service started successfully...
                if (serviceStarted)
                {
                    // Stop the service
                    Thread.Sleep(sleepTime);
                    var serviceStopped = StopService(hService);

                    if (!serviceStopped)
                        Console.Error.WriteLine("Could not stop service {0}", ServiceName);
                }
                else
                    Console.Error.WriteLine("Could not start service {0}", ServiceName);
                // don't return, so we can still delete the service


                // Now delete the service
                Thread.Sleep(sleepTime);
                var serviceDeleted = DeleteService(hService);

                if (!serviceDeleted)
                {
                    Console.Error.WriteLine("Could not delete Service {0}", ServiceName);
                    return false;
                }

                Thread.Sleep(sleepTime);
                CloseHandles(hService, hManager);

                // If we got to the end and didn't start the service, we should return false
                if (!serviceStarted)
                    return false;
                else
                    return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("PSExec Failed: {0}", e.Message);
                return false;
            }
        }

        /// <summary>
        /// Opens the Service Control Manager on the target computer.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <returns>IntPtr. Returns a handle to the SCM.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static IntPtr OpenServiceManager(string ComputerName)
        {
            try
            {
                return Win32.Advapi32.OpenSCManager(ComputerName, null, Win32.Advapi32.SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to open Service Control Manager on {0}", ComputerName + Environment.NewLine + e.Message);
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Creates a new service on the target computer.
        /// </summary>
        /// <param name="hManager">Handle to the SCM.</param>
        /// <param name="ServiceName">The short service name.</param>
        /// <param name="ServiceDisplayName">The friendly display name.</param>
        /// <param name="BinaryPath">The path to the Service Executable.</param>
        /// <returns>IntPtr. Returns a handle to the service.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static IntPtr CreateService(IntPtr hManager, string ServiceName, string ServiceDisplayName, string BinaryPath)
        {
            try
            {
                return Win32.Advapi32.CreateService(hManager, ServiceName, ServiceDisplayName,
                    Win32.Advapi32.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                    Win32.Advapi32.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS,
                    Win32.Advapi32.SERVICE_START.SERVICE_DEMAND_START,
                    Win32.Advapi32.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
                    BinaryPath, null, null, null, null, null);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to create service: {0}", ServiceName + Environment.NewLine + e.Message);
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Starts a service.
        /// </summary>
        /// <param name="hService">The handle to the service.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static bool StartService(IntPtr hService)
        {
            try
            {
                return Win32.Advapi32.StartService(hService, 0, null);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to start service {0}", Environment.NewLine + e.Message);
                return false;
            }
        }

        /// <summary>
        /// Stops a service.
        /// </summary>
        /// <param name="hService">The handle to the service.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static bool StopService(IntPtr hService)
        {
            try
            {
                var serviceStatus = new Win32.Advapi32.SERVICE_STATUS();
                return Win32.Advapi32.ControlService(hService, Win32.Advapi32.SERVICE_CONTROL.STOP, ref serviceStatus);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to stop service {0}", Environment.NewLine + e.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a service.
        /// </summary>
        /// <param name="hService">The handle to the service.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static bool DeleteService(IntPtr hService)
        {
            try
            {
                return Win32.Advapi32.DeleteService(hService);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to delete service {0}", Environment.NewLine + e.Message);
                return false;
            }
        }

        /// <summary>
        /// Closes the handles to the SCM and Service.
        /// </summary>
        /// <param name="hService">The handle to the service.</param>
        /// /// <param name="hManager">The handle to the SCM.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static bool CloseHandles(IntPtr hService, IntPtr hManager)
        {
            try
            {
                Win32.Advapi32.CloseServiceHandle(hManager);
                Win32.Advapi32.CloseServiceHandle(hService);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed to close service handles {0}", Environment.NewLine + e.Message);
                return false;
            }
        }
    }
}