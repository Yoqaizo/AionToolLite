using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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

        private static string Snapshot(StringBuilder sb)
        {
            lock (sb)
            {
                return sb.ToString().TrimEnd();
            }
        }

        public async Task<ProcessResult> RunAsync(
            string executableName,
            IEnumerable<string> arguments,
            CancellationToken cancellationToken = default,
            TimeSpan? timeout = null)
        {
            string fullPath = ResolveSystemExecutable(executableName);
            Encoding enc;
            try { enc = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
            catch { enc = Encoding.UTF8; }

            var psi = new ProcessStartInfo
            {
                FileName = fullPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = enc,
                StandardErrorEncoding = enc
            };

            foreach (var arg in arguments)
                psi.ArgumentList.Add(arg);

            using var proc = new Process { StartInfo = psi };
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            var outDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var errDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data == null) { outDone.TrySetResult(true); return; }
                lock (stdout) { stdout.AppendLine(e.Data); }
            };
            proc.ErrorDataReceived += (_, e) =>
            {
                if (e.Data == null) { errDone.TrySetResult(true); return; }
                lock (stderr) { stderr.AppendLine(e.Data); }
            };

            using var timeoutCts = new CancellationTokenSource(timeout ?? DefaultTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            try
            {
                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                await proc.WaitForExitAsync(linked.Token).ConfigureAwait(false);
                await Task.WhenAll(outDone.Task, errDone.Task)
                    .WaitAsync(TimeSpan.FromSeconds(2), CancellationToken.None)
                    .ConfigureAwait(false);

                return new ProcessResult(proc.ExitCode, Snapshot(stdout), Snapshot(stderr));
            }
            catch (OperationCanceledException)
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }
                return new ProcessResult(-1, Snapshot(stdout), Snapshot(stderr), WasCancelled: true);
            }
            catch (TimeoutException)
            {
                return new ProcessResult(proc.HasExited ? proc.ExitCode : -1, Snapshot(stdout), Snapshot(stderr));
            }
        }
    }
}
