using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using AionToolLite.Services;

namespace AionToolLite
{
    public partial class App : Application
    {
        private const long MaxCrashLogBytes = 256 * 1024;
        private const string MutexName = @"Local\AionToolLite_SingleInstance_Mutex";
        private const string ShowEventName = @"Local\AionToolLite_ShowWindow_Event";

        private static readonly object CrashLogLock = new();
        private static Mutex? _singleInstanceMutex;
        private static EventWaitHandle? _showWindowEvent;
        private static CancellationTokenSource? _ipcCts;
        private static bool _ownsMutex;

        public static bool StartMinimized { get; private set; }
        public static bool IsShuttingDown { get; private set; }

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

        protected override void OnStartup(StartupEventArgs e)
        {
            if (e.Args.Any(a => a.Equals("--uninstall-cleanup", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    var svc = new LiteNetworkService();
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                    svc.PerformUninstallCleanupAsync(cts.Token).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    WriteCrashLog("UninstallCleanup", ex);
                }
                Shutdown(0);
                return;
            }

            StartMinimized = e.Args.Any(a =>
                a.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("-minimized", StringComparison.OrdinalIgnoreCase));

            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
            AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
            SessionEnding += (_, _) =>
            {
                IsShuttingDown = true;
                Shutdown();
            };

            try
            {
                _singleInstanceMutex = new Mutex(true, MutexName, out bool createdNew);
                _ownsMutex = createdNew;
            }
            catch (AbandonedMutexException)
            {
                _ownsMutex = true;
            }
            catch (UnauthorizedAccessException)
            {
                _ownsMutex = false;
            }

            if (!_ownsMutex)
            {
                SignalExistingInstance();
                Shutdown();
                return;
            }

            StartWakeListener();
            base.OnStartup(e);
        }

        private static void SignalExistingInstance()
        {
            try
            {
                using var evt = EventWaitHandle.OpenExisting(ShowEventName);
                evt.Set();
                return;
            }
            catch { }

            try
            {
                using var current = Process.GetCurrentProcess();
                foreach (var proc in Process.GetProcessesByName(current.ProcessName))
                {
                    using (proc)
                    {
                        if (proc.Id != current.Id && proc.MainWindowHandle != IntPtr.Zero)
                        {
                            ShowWindow(proc.MainWindowHandle, 9);
                            SetForegroundWindow(proc.MainWindowHandle);
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        private void StartWakeListener()
        {
            try
            {
                _showWindowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
                _ipcCts = new CancellationTokenSource();
                var token = _ipcCts.Token;

                var thread = new Thread(() =>
                {
                    var handles = new WaitHandle[] { _showWindowEvent, token.WaitHandle };
                    while (!token.IsCancellationRequested)
                    {
                        try
                        {
                            int idx = WaitHandle.WaitAny(handles);
                            if (idx == 0)
                            {
                                Dispatcher.InvokeAsync(() =>
                                {
                                    if (this.MainWindow is AionToolLite.MainWindow mw)
                                        mw.RestoreFromTray();
                                });
                            }
                            else
                            {
                                break;
                            }
                        }
                        catch
                        {
                            break;
                        }
                    }
                })
                {
                    IsBackground = true,
                    Name = "AionToolLite-IPC-Wake"
                };
                thread.Start();
            }
            catch (Exception ex)
            {
                WriteCrashLog("WakeListener", ex);
            }
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            WriteCrashLog("UI", e.Exception);
            try
            {
                MessageBox.Show(
                    $"Something unexpected happened, but AionToolLite caught it safely:\n\n{e.Exception.Message}",
                    "AionToolLite",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            catch { }
            e.Handled = true;
        }

        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            WriteCrashLog("Task", e.Exception);
            e.SetObserved();
        }

        private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                WriteCrashLog("Domain", ex);
                if (e.IsTerminating)
                {
                    try
                    {
                        string innerMsg = ex.InnerException != null
                            ? $"\nInner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}"
                            : string.Empty;
                        MessageBoxW(
                            IntPtr.Zero,
                            $"AionToolLite encountered a startup/runtime error:\n\n{ex.GetType().Name}: {ex.Message}{innerMsg}\n\nDetails saved to %APPDATA%\\AionToolLite\\crash.log",
                            "AionToolLite — Fatal Error",
                            0x00000010);
                    }
                    catch { }
                }
            }
        }

        public static void WriteCrashLog(string source, Exception ex)
        {
            lock (CrashLogLock)
            {
                try
                {
                    string dir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "AionToolLite");
                    Directory.CreateDirectory(dir);
                    string path = Path.Combine(dir, "crash.log");

                    if (File.Exists(path) && new FileInfo(path).Length > MaxCrashLogBytes)
                    {
                        var lines = File.ReadAllLines(path);
                        int skip = Math.Max(0, lines.Length - 150);
                        File.WriteAllLines(path, lines[skip..], new UTF8Encoding(false));
                    }

                    string innerDetails = ex.InnerException != null
                        ? $"{Environment.NewLine}  Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}{Environment.NewLine}{ex.InnerException.StackTrace}"
                        : string.Empty;
                    string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}] {ex.GetType().Name}: {ex.Message}{innerDetails}{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}";
                    File.AppendAllText(path, entry, new UTF8Encoding(false));
                }
                catch { }
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            IsShuttingDown = true;
            try
            {
                _ipcCts?.Cancel();
                _ipcCts?.Dispose();
                _showWindowEvent?.Dispose();
                if (_ownsMutex && _singleInstanceMutex != null)
                    _singleInstanceMutex.ReleaseMutex();
                _singleInstanceMutex?.Dispose();
            }
            catch { }
            base.OnExit(e);
        }
    }
}
