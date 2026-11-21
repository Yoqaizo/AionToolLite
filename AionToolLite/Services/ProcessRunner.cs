using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AionToolLite.Services
{
    public sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError,
        bool WasCancelled = false)
    {
        public bool IsSuccess => ExitCode == 0 && !WasCancelled;
    }

    public sealed class ProcessRunner
    {
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(45);

        [DllImport("kernel32.dll")]
        private static extern uint GetOEMCP();

        // Use blittable byte[] for lpWideCharStr (allocated as charCount * 2 bytes) so CharSet can never cause buffer mis-marshaling
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int MultiByteToWideChar(
            uint codePage,
            uint dwFlags,
            byte[] lpMultiByteStr,
            int cbMultiByte,
            [Out] byte[]? lpWideCharStr,
            int cchWideChar);

        private static string DecodeWindowsOemBytes(byte[] raw)
        {
            if (raw == null || raw.Length == 0)
                return string.Empty;

            if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
                return Encoding.UTF8.GetString(raw, 3, raw.Length - 3).TrimEnd();

            try
            {
                uint oemCp = GetOEMCP();
                if (oemCp == 65001)
                    return Encoding.UTF8.GetString(raw).TrimEnd();

                if (oemCp != 0)
                {
                    int charCount = MultiByteToWideChar(oemCp, 0, raw, raw.Length, null, 0);
                    if (charCount > 0)
                    {
                        var wideBytes = new byte[checked(charCount * 2)];
                        int written = MultiByteToWideChar(oemCp, 0, raw, raw.Length, wideBytes, charCount);
                        if (written > 0 && written <= charCount)
                            return Encoding.Unicode.GetString(wideBytes, 0, written * 2).TrimEnd();
                    }
                }
            }
            catch { }

            return Encoding.UTF8.GetString(raw).TrimEnd();
        }

        private static async Task<byte[]> ReadStreamBytesSafeAsync(Stream stream)
        {
            using var ms = new MemoryStream();
            byte[] buf = new byte[4096];
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buf.AsMemory()).ConfigureAwait(false)) > 0)
                {
                    ms.Write(buf, 0, read);
                }
            }
            catch { }
            return ms.ToArray();
        }

        public string ResolveSystemExecutable(string executableName)
        {
            if (string.IsNullOrWhiteSpace(executableName))
                throw new ArgumentException("Executable name cannot be empty.");

            if (executableName.Contains(Path.DirectorySeparatorChar) ||
                executableName.Contains(Path.AltDirectorySeparatorChar) ||
                executableName.Contains("..") ||
                executableName.IndexOf('\0') >= 0)
                throw new ArgumentException("Custom paths are not allowed.");

            string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string clean = executableName.Trim();
            string exeWithExt = clean.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? clean : clean + ".exe";

            string fullPath;
            if (exeWithExt.Equals("notepad.exe", StringComparison.OrdinalIgnoreCase))
            {
                string sysNotepad = Path.Combine(sysDir, "notepad.exe");
                fullPath = File.Exists(sysNotepad) ? sysNotepad : Path.Combine(winDir, "notepad.exe");
            }
            else
            {
                fullPath = Path.Combine(sysDir, exeWithExt);
            }

            if (!File.Exists(fullPath))
                throw new FileNotFoundException($"System tool not found: {fullPath}", fullPath);

            return fullPath;
        }

        public async Task<ProcessResult> RunAsync(
            string executableName,
            IEnumerable<string> arguments,
            CancellationToken cancellationToken = default,
            TimeSpan? timeout = null)
        {
            string fullPath = ResolveSystemExecutable(executableName);

            var psi = new ProcessStartInfo
            {
                FileName = fullPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            foreach (var arg in arguments)
                psi.ArgumentList.Add(arg);

            using var proc = new Process { StartInfo = psi };
            using var timeoutCts = new CancellationTokenSource(timeout ?? DefaultTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            Task<byte[]>? outTask = null;
            Task<byte[]>? errTask = null;

            try
            {
                proc.Start();
                outTask = ReadStreamBytesSafeAsync(proc.StandardOutput.BaseStream);
                errTask = ReadStreamBytesSafeAsync(proc.StandardError.BaseStream);

                await proc.WaitForExitAsync(linked.Token).ConfigureAwait(false);
                await Task.WhenAll(outTask, errTask)
                    .WaitAsync(TimeSpan.FromSeconds(2), CancellationToken.None)
                    .ConfigureAwait(false);

                return new ProcessResult(
                    proc.ExitCode,
                    DecodeWindowsOemBytes(outTask.Result),
                    DecodeWindowsOemBytes(errTask.Result));
            }
            catch (OperationCanceledException)
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }
                string outStr = outTask != null && outTask.IsCompletedSuccessfully ? DecodeWindowsOemBytes(outTask.Result) : string.Empty;
                string errStr = errTask != null && errTask.IsCompletedSuccessfully ? DecodeWindowsOemBytes(errTask.Result) : string.Empty;
                return new ProcessResult(-1, outStr, errStr, WasCancelled: true);
            }
            catch (TimeoutException)
            {
                string outStr = outTask != null && outTask.IsCompletedSuccessfully ? DecodeWindowsOemBytes(outTask.Result) : string.Empty;
                string errStr = errTask != null && errTask.IsCompletedSuccessfully ? DecodeWindowsOemBytes(errTask.Result) : string.Empty;
                return new ProcessResult(proc.HasExited ? proc.ExitCode : -1, outStr, errStr);
            }
        }
    }
}
