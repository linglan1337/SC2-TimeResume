// =============================================================================
//  SC2 时间恢复（仅恢复版）
//  作者：铃兰
//
//  与 SC2ResumeGui.cs 的差异：
//    - 只保留“解除时间暂停”一个按钮，不含暂停功能
//    - 其余逻辑（进程检测、版本校验、高频调用、时长设置、中途停止）完全一致
//    - 适合只做“反制”用途、不需要主动暂停的场景
//
//  同样锁定 StarCraft II 5.0.15.98370（Base98370），换版本需重新定位恢复入口。
// =============================================================================
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

internal static class Sc2TimeResumeApp
{
    // ---------------------------------------------------------------------
    // 目标构建信息
    // ---------------------------------------------------------------------
    // 这几个常量把程序“钉死”在唯一一个游戏版本上。换版本必须全部重新核对，
    // 否则 RVA 会指向错误的指令，可能直接导致游戏崩溃。
    private const string ExpectedPath = @"D:\StarCraft II\Versions\Base98370\SC2_x64.exe";
    private const string ExpectedVersion = "5.0.15.98370";

    // 完整文件哈希：比版本号可靠，能识别出被替换/修改过的 exe。
    private const string ExpectedSha256 = "C68202849F8E64ED20D15BEA0FB89F2C5B94028D075D9848E124A8264D130222";

    // ---------------------------------------------------------------------
    // “恢复 / 取消暂停”函数入口
    // ---------------------------------------------------------------------
    // RVA（相对镜像基址的偏移）：运行时实际地址 = 模块基址 + RVA。
    // 调用约定为 __fastcall，第 1 个参数在 ecx，这里统一传 0。
    //
    // ResumeFileOffset 是同一个函数在磁盘文件中的偏移，用于启动前校验
    // 该位置的指令是否仍为预期内容，防止把旧地址用到新版本上。
    private const int ResumeRva = 0x009EB090;
    private const int ResumeFileOffset = 0x009EA890;

    // 函数开头 25 个字节的指纹，唯一确认版本。少一个字节都可能与其他函数混淆。
    private static readonly byte[] ResumePrefix = Hex("40534883EC208B155CA A0A058BD981C2BCA3D51103150A4F4C03".Replace(" ", ""));

    // 打开游戏进程所需的权限位：
    //   0x0002 PROCESS_CREATE_THREAD      —— 创建远程线程（核心）
    //   0x0008 PROCESS_VM_OPERATION       —— 内存操作（线程需要）
    //   0x0010 PROCESS_VM_READ            —— 读取内存（用于定位模块）
    //   0x0400 PROCESS_QUERY_INFORMATION  —— 查询进程信息
    private const uint RequiredAccess = 0x0002 | 0x0008 | 0x0010 | 0x0400;
    private const uint WaitObject0 = 0;      // WaitForSingleObject 返回 0 = 已结束
    private const uint WaitTimeout = 0x102;  // WAIT_TIMEOUT

    // ---------------------------------------------------------------------
    // Win32 API 声明
    // ---------------------------------------------------------------------
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr process, IntPtr attributes,
        UIntPtr stackSize, IntPtr startAddress, IntPtr parameter, uint flags, out uint threadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(IntPtr processHandle, IntPtr jobHandle, out bool result);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int value, int length, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returnLength);
    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder text, ref int size);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    /// <summary>窗口枚举：不依赖进程枚举通道，受限视图下也能发现游戏窗口。
    /// 实测该版本 SC2 的窗口类名是 "StarCraft II"（不是 "SC2"），标题是 "《星际争霸II》"。</summary>
    private static int FindSc2WindowPid()
    {
        int found = 0;
        try
        {
            EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
            {
                StringBuilder cls = new StringBuilder(256);
                if (GetClassName(hWnd, cls, cls.Capacity) == 0) return true;
                string klass = cls.ToString();
                StringBuilder title = new StringBuilder(256);
                GetWindowText(hWnd, title, title.Capacity);
                string caption = title.ToString();
                bool hit = klass.IndexOf("StarCraft", StringComparison.OrdinalIgnoreCase) >= 0
                    || caption.IndexOf("StarCraft", StringComparison.OrdinalIgnoreCase) >= 0
                    || caption.IndexOf("星际争霸", StringComparison.Ordinal) >= 0;
                if (!hit) return true;
                uint pid;
                GetWindowThreadProcessId(hWnd, out pid);
                if (pid == 0) return true;
                // 必须确认该窗口属于游戏进程，否则工具自身或其它标题含关键字的窗口会被误认。
                string pname = null;
                try { using (Process p = Process.GetProcessById((int)pid)) pname = p.ProcessName; }
                catch { }
                if (!String.IsNullOrEmpty(pname)
                    && !String.Equals(pname, "SC2_x64", StringComparison.OrdinalIgnoreCase)
                    && !String.Equals(pname, "SC2", StringComparison.OrdinalIgnoreCase))
                    return true;
                found = (int)pid;
                return false; // 找到就停
            }, IntPtr.Zero);
        }
        catch { }
        return found;
    }

    /// <summary>按 PID 取映像路径：先走托管方式，失败再用 LIMITED_INFORMATION 直读。</summary>
    private static string ProcessImagePath(int pid)
    {
        try
        {
            using (Process p = Process.GetProcessById(pid)) return p.MainModule.FileName;
        }
        catch { }
        IntPtr h = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            StringBuilder sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString(0, size);
            return null;
        }
        finally { CloseHandle(h); }
    }

    private static string EnvironmentInfo()
    {
        string job = "未知";
        try
        {
            bool inJob;
            if (IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob)) job = inJob ? "是" : "否";
        }
        catch { }

        string elevated = "未知";
        try
        {
            IntPtr token;
            if (OpenProcessToken(GetCurrentProcess(), 0x0008, out token))
            {
                int value, returned;
                if (GetTokenInformation(token, 20, out value, 4, out returned))
                    elevated = value != 0 ? "是" : "否";
                CloseHandle(token);
            }
        }
        catch { }

        return "在作业对象中=" + job + " 已提权=" + elevated + " 完整性=0x" + IntegrityLevel().ToString("X");
    }

    /// <summary>令牌的完整性级别 RID：0x1000=中，0x2000=高，0x3000=系统级高（管理员提升后）。</summary>
    private static int IntegrityLevel()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out token)) return 0;
        try
        {
            int need, returned;
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out need);
            if (need <= 0) return 0;
            IntPtr buffer = Marshal.AllocHGlobal(need);
            try
            {
                if (!GetTokenInformation(token, 25, buffer, need, out returned)) return 0;
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                byte count = Marshal.ReadByte(sid, 1);
                if (count < 1) return 0;
                return Marshal.ReadInt32(sid, 8 + (count - 1) * 4);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch { return 0; }
        finally { CloseHandle(token); }
    }

    private static bool IsElevatedToken()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out token)) return false;
        try
        {
            int value, returned;
            if (GetTokenInformation(token, 20, out value, 4, out returned)) return value != 0;
            return false;
        }
        catch { return false; }
        finally { CloseHandle(token); }
    }

    /// <summary>
    /// 真正可用的管理员身份 = 令牌已提升 且 完整性级别达到系统级高。
    /// 只看 WindowsPrincipal.IsInRole(Administrator) 是不够的：UAC 过滤后的令牌里
    /// 管理员组仍在（deny-only），判断会返回 true，程序就会以中完整性继续跑，
    /// 结果是只能看见几十个进程、永远找不到游戏。
    /// </summary>
    private static bool IsReallyElevated()
    {
        // 完整性级别：0x1000=低(沙箱) 0x2000=中 0x3000=高(管理员提升) 0x4000=系统。
        // 必须达到“高”才能读取并操作高完整性的游戏进程；低/中完整性一律视为未就绪。
        try { return IsElevatedToken() && IntegrityLevel() >= 0x3000; }
        catch { return false; }
    }

    private static byte[] Hex(string value)
    {
        byte[] bytes = new byte[value.Length / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static string HashFile(string path)
    {
        using (SHA256 sha = SHA256.Create())
        using (FileStream stream = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
    }

    /// <summary>
    /// 按“文件版本”而不是安装路径识别目标构建：游戏可能装在任何盘符/目录，
    /// 硬编码路径会把正常安装误判为“不支持的版本”。
    /// </summary>
    private static bool IsTargetBuild(string path)
    {
        try
        {
            if (String.IsNullOrEmpty(path)) return false;
            if (!String.Equals(Path.GetFileName(path), "SC2_x64.exe", StringComparison.OrdinalIgnoreCase)) return false;
            // 必须用 FileVersion 字符串：VS_FIXEDFILEINFO 的 Build/Private 段
            // 与字符串最后两段并不对应（实测 5.0.15.98370 拆出来是 5.0.15.32834）。
            return String.Equals(FileVersion(path), ExpectedVersion, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static string FileVersion(string path)
    {
        try
        {
            FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
            return (vi.FileVersion ?? "").Trim();
        }
        catch { return ""; }
    }

    private static string BuildLabel(string path)
    {
        string v = FileVersion(path);
        return v.Length == 0 ? "?" : v;
    }


    /// <summary>
    /// 三重校验，任何一项不通过都拒绝执行：
    ///   1) 文件名必须是 SC2_x64.exe
    ///   2) 整个文件的 SHA-256 必须与记录一致（识别替换/修改）
    ///   3) 恢复入口处的指令字节必须与记录一致（识别版本漂移）
    ///
    /// 第 3 项是关键：即使哈希因某种原因被忽略，只要入口指令不是预期的样子，
    /// 就绝不把 RVA 当作函数地址去调用——否则会跳进指令中间导致崩溃。
    /// 返回 null 表示校验通过，否则返回说明文字。
    /// </summary>
    private static string VerifyBuild(string path)
    {
        try
        {
            if (String.IsNullOrEmpty(path))
                return "拒绝：读不到游戏程序路径。";
            if (!String.Equals(Path.GetFileName(path), "SC2_x64.exe", StringComparison.OrdinalIgnoreCase))
                return "拒绝：目标不是 SC2_x64.exe。";
            if (!String.Equals(HashFile(path), ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                return "拒绝：游戏文件哈希与已核对的 Base98370 构建不符（当前: "
                    + BuildLabel(path) + "）。请换用已核对的版本。";
            using (FileStream stream = File.OpenRead(path))
            {
                // 直接读磁盘文件里的机器码，不依赖进程内存，避免运行时被修改干扰。
                stream.Position = ResumeFileOffset;
                byte[] bytes = new byte[ResumePrefix.Length];
                if (stream.Read(bytes, 0, bytes.Length) != bytes.Length) return "拒绝：读取恢复入口签名失败。";
                for (int i = 0; i < bytes.Length; i++)
                    if (bytes[i] != ResumePrefix[i]) return "拒绝：恢复入口签名不匹配。";
            }
            return null;
        }
        catch (Exception ex) { return "版本验证失败：" + ex.Message; }
    }

    private sealed class MainForm : Form
    {
        private readonly Button recover = new Button();
        private readonly StatusStrip statusBar = new StatusStrip();
        private readonly ToolStripStatusLabel statusLabel = new ToolStripStatusLabel();
        private readonly System.Windows.Forms.Timer processTimer = new System.Windows.Forms.Timer();
        private int scanCount;
        private int missingRounds;
        private int detectedPid;

        private readonly NumericUpDown durationBox = new NumericUpDown();
        private volatile bool stopFlag;
        private bool running;

        public MainForm()
        {
            Text = "SC2时间恢复 - By铃兰";
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = true;
            ClientSize = new Size(390, 186);
            Font = new Font("Microsoft YaHei UI", 9F);

            recover.Text = "点击解除时间暂停";
            recover.Font = new Font(Font.FontFamily, 12F, FontStyle.Bold);
            recover.Size = new Size(340, 52);
            recover.Location = new Point(25, 18);
            recover.Click += delegate { InvokeAction(false); };
            Controls.Add(recover);

            Label durLabel = new Label();
            durLabel.Text = "持续时长（秒）";
            durLabel.AutoSize = true;
            durLabel.Location = new Point(25, 88);
            Controls.Add(durLabel);

            durationBox.Minimum = 1;
            durationBox.Maximum = 600;
            durationBox.Value = 5;
            durationBox.Increment = 5;
            durationBox.Location = new Point(140, 84);
            durationBox.Size = new Size(80, 26);
            durationBox.TextAlign = HorizontalAlignment.Center;
            Controls.Add(durationBox);

            Label tip = new Label();
            tip.Text = "运行中再点一次按钮可立即停止";
            tip.AutoSize = true;
            tip.ForeColor = Color.DimGray;
            tip.Location = new Point(25, 122);
            Controls.Add(tip);

            statusBar.Dock = DockStyle.Bottom;
            statusBar.SizingGrip = false;
            statusLabel.Spring = true;
            statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            statusBar.Items.Add(statusLabel);
            Controls.Add(statusBar);

            processTimer.Interval = 500;
            statusLabel.Text = "正在检测SC2进程…";
            statusLabel.ForeColor = Color.DarkOrange;
            processTimer.Tick += delegate { RefreshProcessStatus(); };
            Shown += delegate
            {
                RefreshProcessStatus();
                processTimer.Start();
            };
            FormClosed += delegate { processTimer.Stop(); processTimer.Dispose(); };
        }

        private static readonly object logLock = new object();

        private static string LogPath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "detect_log.txt"); }
        }

        private static void WriteDiagnostic(int round, int scanned, bool found, int pid,
            bool unreadable, bool otherPath, bool sc2Named, string detail)
        {
            // 只在首轮、或状态变化时写入，避免日志膨胀。
            bool interesting = round == 1 || round % 20 == 0 || found || sc2Named || detail.Length > 0;
            if (!interesting) return;
            try
            {
                string line = String.Format(
                    "{0:yyyy-MM-dd HH:mm:ss} 轮次={1} 扫描数={2} 目标={3} PID={4} 不可读={5} 其他路径={6} SC2名字={7} 备注={8}\r\n",
                    DateTime.Now, round, scanned, found, pid, unreadable, otherPath, sc2Named,
                    detail.Length == 0 ? "-" : detail);
                lock (logLock)
                {
                    if (round == 1)
                        File.WriteAllText(LogPath,
                            "SC2 检测诊断日志\r\n进程=" + Process.GetCurrentProcess().ProcessName +
                            " 会话=" + Process.GetCurrentProcess().SessionId +
                            " 路径=" + AppDomain.CurrentDomain.BaseDirectory +
                            "\r\n完整性=" + IntegrityLevel().ToString("X4") +
                            "（0x1000低/0x2000中/0x3000高/0x4000系统）" +
                            "\r\n环境=" + EnvironmentInfo() +
                            "\r\n对照：若任务管理器能看到 SC2_x64 而本程序扫描数很低，说明本程序处在受限进程视图。\r\n\r\n",
                            Encoding.UTF8);
                    File.AppendAllText(LogPath, line, Encoding.UTF8);
                }
            }
            catch { }
        }

        private static bool IsGameProcessName(string name)
        {
            return String.Equals(name, "SC2_x64", StringComparison.OrdinalIgnoreCase)
                || String.Equals(name, "SC2", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExpectedPath(string path)
        {
            try { return String.Equals(Path.GetFullPath(path), ExpectedPath, StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        private void RefreshProcessStatus()
        {
            scanCount++;
            bool foundTarget = false;
            bool unreadable = false;
            bool otherPath = false;
            bool sc2Named = false;
            int targetPid = 0;
            int scanned = 0;
            string detail = "";
            string seenVersion = "?";

            // 通道 1：全量进程枚举
            Process[] all = null;
            try
            {
                all = Process.GetProcesses();
                scanned = all.Length;
            }
            catch (Exception ex) { detail = "枚举失败:" + ex.Message; }
            if (all != null)
            {
                try
                {
                    foreach (Process p in all)
                    {
                        string name = null;
                        try { name = p.ProcessName; } catch { continue; }
                        if (!IsGameProcessName(name)) continue;
                        sc2Named = true;
                        try
                        {
                            string path = p.MainModule.FileName;
                            if (IsTargetBuild(path)) { foundTarget = true; targetPid = p.Id; }
                            else { otherPath = true; seenVersion = BuildLabel(path); }
                        }
                        catch { unreadable = true; }
                    }
                }
                finally { foreach (Process p in all) p.Dispose(); }
            }

            // 通道 2：按进程名查询
            if (!foundTarget)
            {
                foreach (string probe in new string[] { "SC2_x64", "SC2" })
                {
                    Process[] named = null;
                    try { named = Process.GetProcessesByName(probe); } catch { }
                    if (named == null) continue;
                    try
                    {
                        foreach (Process p in named)
                        {
                            sc2Named = true;
                            try
                            {
                                string path = p.MainModule.FileName;
                                if (IsTargetBuild(path)) { foundTarget = true; targetPid = p.Id; }
                                else { otherPath = true; seenVersion = BuildLabel(path); }
                            }
                            catch { unreadable = true; }
                        }
                    }
                    finally { foreach (Process p in named) p.Dispose(); }
                }
            }

            // 通道 3：窗口枚举。进程枚举可能被完整性级别裁剪，但顶层窗口仍可枚举，
            // 因此这条通道能在受限视图下认出“游戏其实在运行”，把误报降级为“读不到路径”。
            if (!foundTarget)
            {
                int windowPid = FindSc2WindowPid();
                if (windowPid > 0)
                {
                    sc2Named = true;
                    string windowPath = ProcessImagePath(windowPid);
                    if (String.IsNullOrEmpty(windowPath)) unreadable = true;
                    else if (IsTargetBuild(windowPath)) { foundTarget = true; targetPid = windowPid; }
                    else { otherPath = true; seenVersion = BuildLabel(windowPath); }
                    detectedPid = windowPid;
                }
            }

            // 通道 4：WMI，可跨会话看到进程
            if (!foundTarget)
            {
                try
                {
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                        "SELECT ProcessId, Name, ExecutablePath FROM Win32_Process WHERE Name LIKE 'SC2%'"))
                    using (ManagementObjectCollection rows = searcher.Get())
                    {
                        foreach (ManagementBaseObject row in rows)
                        {
                            object nameValue = row["Name"];
                            string name = nameValue == null ? "" : nameValue.ToString();
                            if (!name.StartsWith("SC2", StringComparison.OrdinalIgnoreCase)) continue;
                            if (!IsGameProcessName(Path.GetFileNameWithoutExtension(name))) continue;
                            sc2Named = true;
                            object pathValue = row["ExecutablePath"];
                            string path = pathValue == null ? null : pathValue.ToString();
                            if (String.IsNullOrEmpty(path)) { unreadable = true; continue; }
                            if (IsTargetBuild(path))
                            {
                                foundTarget = true;
                                object pidValue = row["ProcessId"];
                                targetPid = pidValue == null ? 0 : Convert.ToInt32(pidValue);
                            }
                            else { otherPath = true; seenVersion = BuildLabel(path); }
                        }
                    }
                }
                catch (Exception ex) { if (detail.Length == 0) detail = "WMI:" + ex.Message; }
            }

            WriteDiagnostic(scanCount, scanned, foundTarget, targetPid, unreadable, otherPath, sc2Named, detail);

            string stamp = DateTime.Now.ToString("HH:mm:ss");
            if (foundTarget)
            {
                missingRounds = 0;
                // 记住状态栏认定的 PID：执行阶段优先用它，避免再次枚举时因视图受限而丢失。
                detectedPid = targetPid;
                bool elevated = IsReallyElevated();
                // 只要认出了游戏就允许点击；权限不足在点击时提示并请求提权，
                // 而不是在这里把按钮锁死——否则用户会完全无法操作。
                recover.Enabled = true;
                statusLabel.Text = "SC2运行中 · PID " + targetPid
                    + (elevated ? "" : " · 未提权，点击会请求管理员权限");
                statusLabel.ForeColor = elevated ? Color.DarkGreen : Color.DarkOrange;
            }
            else if (unreadable)
            {
                missingRounds = 0;
                recover.Enabled = true;
                statusLabel.Text = "发现SC2进程，但读不到程序路径";
                statusLabel.ForeColor = Color.DarkOrange;
            }
            else if (otherPath)
            {
                missingRounds = 0;
                recover.Enabled = true;
                statusLabel.Text = "SC2版本 " + seenVersion + "，非支持的 " + ExpectedVersion;
                statusLabel.ForeColor = Color.DarkOrange;
            }
            else if (sc2Named)
            {
                missingRounds = 0;
                recover.Enabled = true;
                statusLabel.Text = "发现SC2进程，但未能定位";
                statusLabel.ForeColor = Color.DarkOrange;
            }
            else
            {
                missingRounds++;
                recover.Enabled = false;
                // 中完整性令牌的进程视图会被裁剪（本机实测：中=46~48，高=320+）。
                // 这时“没找到”并不等于“没运行”，必须说清楚，否则会一直误报。
                bool viewLimited = scanned > 0 && scanned < 80;
                if (missingRounds < 3)
                {
                    statusLabel.Text = "正在检测SC2…";
                    statusLabel.ForeColor = Color.DarkOrange;
                }
                else if (viewLimited)
                {
                    statusLabel.Text = "进程视图受限（仅 " + scanned + " 个），看不到游戏 · 请以管理员身份运行";
                    statusLabel.ForeColor = Color.Firebrick;
                }
                else
                {
                    statusLabel.Text = "SC2未运行"
                        + (detail.Length > 0 ? " · " + detail : "");
                    statusLabel.ForeColor = Color.Firebrick;
                }
            }
        }

        private async void InvokeAction(bool pauseAction)
        {
            // 本版本只保留“恢复”，暂停按钮已移除。
            string name = "恢复";

            // 已在运行：再点一次 = 停止，避免反复点击造成崩溃。
            if (running)
            {
                stopFlag = true;
                recover.Text = "正在停止…";
                return;
            }

            if (!IsReallyElevated())
            {
                int il = IntegrityLevel();
                string level = il >= 0x4000 ? "系统" : il >= 0x3000 ? "高（管理员）"
                    : il >= 0x2000 ? "中（普通用户）" : "低（沙箱/受限）";
                MessageBox.Show(this,
                    "当前无法操作游戏进程。\n\n" +
                    "本程序完整性级别：0x" + il.ToString("X") + "（" + level + "）\n" +
                    "游戏进程为 0x3000（高），需要同级权限才能调用。\n\n" +
                    "请关掉本窗口，改用下面任一方式重新打开本程序：\n" +
                    "  1) 打开「此电脑」，进到本 exe 所在文件夹，直接双击；\n" +
                    "  2) 任务管理器 → 文件 → 运行新任务 → 勾选「以系统管理权限创建此任务」→ 浏览本 exe。\n\n" +
                    "注意：本机 UAC 已关闭，右键「以管理员身份运行」不会真正提权，请用上面两种方式。",
                    "需要以高完整性运行", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int seconds = (int)durationBox.Value;
            DialogResult confirm = MessageBox.Show(this,
                "仅在你控制、参与者知情的私人测试房使用。\n" +
                "将对检测到的 SC2 进程持续执行【" + name + "】，时长 " + seconds + " 秒。\n" +
                "运行中再点一次按钮可立即停止。\n\n继续？",
                "私人测试确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            running = true;
            stopFlag = false;
            recover.Text = "停止恢复";
            statusLabel.Text = "正在持续" + name + "（" + seconds + " 秒）…";
            statusLabel.ForeColor = Color.DarkOrange;
            try
            {
                string result = await Task.Factory.StartNew<string>(() => RunBounded(ResumeRva, name, seconds));
                MessageBox.Show(this, result, name + "结果", MessageBoxButtons.OK,
                    result.Contains("成功") ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "测试失败：" + ex.Message, "测试失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                running = false;
                recover.Enabled = true;
                recover.Text = "点击解除时间暂停";
                statusLabel.Text = "已停止" + name;
                statusLabel.ForeColor = Color.DimGray;
            }
        }

        private string RunBounded(int rva, string actionName, int seconds)
        {
            if (!IsReallyElevated())
                return "当前是受限进程视图（完整性 0x" + IntegrityLevel().ToString("X") +
                    "），无法对游戏进程建立远程线程。请右键 → 以管理员身份运行后重试。\n" +
                    "未对进程作任何调用。";

            Process selected = null;
            int pid = detectedPid;

            // 优先用状态栏已经认出来的 PID（窗口枚举通道在受限视图下也能定位）。
            if (pid > 0)
            {
                string known = ProcessImagePath(pid);
                // 受限视图下常常读不到进程模块路径，此时退回用磁盘上的已知安装路径做校验。
                if (String.IsNullOrEmpty(known) && File.Exists(ExpectedPath)) known = ExpectedPath;
                if (!String.IsNullOrEmpty(known) && IsTargetBuild(known))
                {
                    try { selected = Process.GetProcessById(pid); }
                    catch { selected = null; }
                }
            }

            Process[] candidates = null;
            string seenInfo = "";
            try
            {
                if (selected == null)
                {
                    candidates = Process.GetProcessesByName("SC2_x64");
                    if (candidates.Length == 0) seenInfo = "按名称未找到 SC2_x64";
                    foreach (Process p in candidates)
                    {
                        string path = ProcessImagePath(p.Id);
                        if (String.IsNullOrEmpty(path))
                        {
                            if (seenInfo.Length == 0) seenInfo = "PID " + p.Id + " 路径不可读";
                            continue;
                        }
                        if (!IsTargetBuild(path))
                        {
                            seenInfo = "PID " + p.Id + " 版本 " + BuildLabel(path);
                            continue;
                        }
                        if (selected != null)
                            return "检测到多个目标游戏实例。请关闭多余实例后再试。";
                        selected = p;
                        pid = p.Id;
                    }
                }

                if (selected == null)
                {
                    int visible = 0;
                    try { visible = Process.GetProcesses().Length; } catch { }
                    return "未定位到目标游戏（" +
                        (seenInfo.Length == 0 ? "按名称未找到 SC2_x64" : seenInfo) +
                        "）。\n\n诊断：本程序当前可见 " + visible + " 个进程，完整性级别 0x" +
                        IntegrityLevel().ToString("X") + "。\n" +
                        "若任务管理器能看到 SC2_x64 而这里看不到，说明本程序处于受限进程视图，" +
                        "请用资源管理器右键该 exe →「以管理员身份运行」后再试。";
                }

                string targetPath = ProcessImagePath(selected.Id);
                if (String.IsNullOrEmpty(targetPath) && File.Exists(ExpectedPath)) targetPath = ExpectedPath;
                string verify = VerifyBuild(targetPath);
                if (verify != null) return verify;

                pid = selected.Id;
                IntPtr moduleBase;
                try { moduleBase = selected.MainModule.BaseAddress; }
                catch (Exception ex)
                {
                    return "已定位到游戏（PID " + pid + "），但读不到模块基址：请在管理员权限下运行。\n" + ex.Message;
                }
                IntPtr process = OpenProcess(RequiredAccess, false, pid);
                if (process == IntPtr.Zero)
                    return "打开游戏进程失败，Win32=" + Marshal.GetLastWin32Error() + "。请使用同等权限重新启动。";

                int attempts = 0, returned = 0, timeouts = 0;
                // 高频模式：不设固定间隔，创建后只做 5ms 回收等待；线程未结束也继续下一次。
                const int maxAttempts = 500000;
                DateTime until = DateTime.UtcNow.AddSeconds(seconds);
                try
                {
                    while (DateTime.UtcNow < until && attempts < maxAttempts && !stopFlag)
                    {
                        if (selected.HasExited) return "目标游戏已退出；停止测试。";
                        uint threadId;
                        IntPtr thread = CreateRemoteThread(process, IntPtr.Zero, UIntPtr.Zero,
                            IntPtr.Add(moduleBase, rva), IntPtr.Zero, 0, out threadId);
                        attempts++;
                        if (thread == IntPtr.Zero)
                            return actionName + "调用创建失败，Win32=" + Marshal.GetLastWin32Error();
                        try
                        {
                            uint wait = WaitForSingleObject(thread, 5);
                            if (wait == WaitObject0) returned++;
                            else timeouts++;
                        }
                        finally { CloseHandle(thread); }
                    }
                }
                finally { CloseHandle(process); }
                return "恢复" + (stopFlag ? "已停止" : "成功") + "，持续发包时间为" + seconds + "s（共 " + attempts + " 次）";
            }
            finally
            {
                if (candidates != null)
                    foreach (Process p in candidates)
                        if (p != selected) { try { p.Dispose(); } catch { } }
                if (selected != null) { try { selected.Dispose(); } catch { } }
            }
        }
    }

    private static void Main(string[] args)
    {
        bool alreadyElevatedAttempt = false;
        bool diagnose = false;
        foreach (string arg in args)
        {
            if (String.Equals(arg, "--elevated", StringComparison.OrdinalIgnoreCase)) alreadyElevatedAttempt = true;
            if (String.Equals(arg, "--diagnose", StringComparison.OrdinalIgnoreCase)) diagnose = true;
        }

        // 诊断模式：不弹窗、不提权，把当前令牌/进程视图/窗口通道的结果写成报告。
        if (diagnose)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("时间: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            report.AppendLine("环境: " + EnvironmentInfo());
            report.AppendLine("真正提权: " + IsReallyElevated());
            int scanned = 0;
            try { scanned = Process.GetProcesses().Length; } catch { }
            report.AppendLine("进程视图: " + scanned + " 个");
            int windowPid = FindSc2WindowPid();
            report.AppendLine("窗口通道 PID: " + windowPid);
            if (windowPid > 0) report.AppendLine("窗口通道路径: " + (ProcessImagePath(windowPid) ?? "(读不到)"));
            int named = 0;
            try { named = Process.GetProcessesByName("SC2_x64").Length; } catch { }
            report.AppendLine("按名通道: " + named + " 个");
            string target = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "diagnose_report.txt");
            try { File.WriteAllText(target, report.ToString(), Encoding.UTF8); } catch { }
            return;
        }

        if (!IsReallyElevated())
        {
            if (!alreadyElevatedAttempt)
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = Process.GetCurrentProcess().MainModule.FileName,
                        UseShellExecute = true,
                        Verb = "runas",
                        Arguments = "--elevated"
                    });
                    return;
                }
                catch (Exception ex)
                {
                    // 常见于用户在 UAC 里点了“否”（Win32 1223）。继续以受限视图运行，
                    // 但会在状态栏与日志里明确写出“进程视图受限”，不再误报“SC2未运行”。
                    MessageBox.Show("未能取得管理员权限，程序将以受限进程视图运行：\n" +
                        "这种情况下通常只能看见几十个进程，读不到 SC2（它运行在更高的完整性级别）。\n\n" +
                        "建议右键 → 以管理员身份运行。\n\n" + ex.Message,
                        "权限不足", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            else
            {
                MessageBox.Show("已请求管理员权限，但当前令牌仍未达到管理员完整性级别。\n" +
                    "程序会继续运行，但可能看不到游戏进程。",
                    "权限仍受限", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
