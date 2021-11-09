using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.Threading;

namespace EncryptUser_.net_WFP_
{
    /// <summary>
    /// AddProcessRules.xaml 的交互逻辑
    /// </summary>
    public partial class AddProcessRules : Window
    {
        public AddProcessRules()
        {
            InitializeComponent();
        }

        [DllImport("EncryptUserDLL.dll")]
        static extern int EptUserInitCommPort(ref IntPtr hPort);
        [DllImport("EncryptUserDLL.dll")]
        static extern int EptUserGetMessage(IntPtr hPort, ref uint Command);
        [DllImport("EncryptUserDLL.dll")]
        static extern int EptAddProcessRules(IntPtr hPort, string ProcessName, string ExtensionName, int count, int Access, bool isCheckHash);
        [DllImport("Kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        const uint STATUS_SUCCESS = 0x00000000;
        const uint EPT_ALREADY_HAVE_ENCRYPT_HEADER = 0xFFFFFFFA;
        const int EPT_PRIVILEGE_ENCRYPT = 8;
        const int EPT_PRIVILEGE_DECRYPT = 4;
        const uint EPT_APPEND_ENCRYPT_HEADER = 0xFFFFFFF8;
        const uint EPT_DONT_HAVE_ENCRYPT_HEADER = 0xFFFFFFF6;
        const uint EPT_REMOVE_ENCRYPT_HEADER = 0xFFFFFFF5;

        const uint EPT_SAME_PR_ALREADY_EXISTS = 0xFFFFFFF4;
        const uint EPT_UPDATE_PR = 0xFFFFFFF3;
        const uint EPT_INSERT_PR = 0xFFFFFFF2;


        const int EPT_PR_ACCESS_READ_WRITE = 0x00000001;
        const int EPT_PR_ACCESS_BACKUP_RESTORE = 0x00000002;
        const int EPT_PR_ACCESS_NO_ACCESS = 0x00000004;


        private static IntPtr hPort;

        private void GetMessageThread()
        {
            uint ReturnCommand = 0;
            EptUserGetMessage(hPort, ref ReturnCommand);

            if (EPT_ALREADY_HAVE_ENCRYPT_HEADER == ReturnCommand)
            {
                MessageBox.Show("File has already been encrypted.");
            }
            else if (EPT_APPEND_ENCRYPT_HEADER == ReturnCommand)
            {
                MessageBox.Show("File is privilegely encrypted successfully.");
            }
            else if (EPT_DONT_HAVE_ENCRYPT_HEADER == ReturnCommand)
            {
                MessageBox.Show("File isn't a encrypted file.");
            }
            else if (EPT_REMOVE_ENCRYPT_HEADER == ReturnCommand)
            {
                MessageBox.Show("File is privilegely decrypted successfully.");
            }
            else if (EPT_SAME_PR_ALREADY_EXISTS == ReturnCommand)
            {
                MessageBox.Show("The same process rule already exists. Insert or update unsuccessfully.");
            }
            else if (EPT_UPDATE_PR == ReturnCommand)
            {
                MessageBox.Show("Process rule already exists. Update it successfully.");
            }
            else if (EPT_INSERT_PR == ReturnCommand)
            {
                MessageBox.Show("Process rule is inserted successfully.");
            }
            else
            {
                string ErrorText = "failed!->File is privilegely encrypted unsuccessfully. ReturnCommand = %d";
                ErrorText = ErrorText + ReturnCommand.ToString();
                MessageBox.Show(ErrorText);
            }

            if (0 != hPort.ToInt32())
            {
                //MessageBox.Show("hPort close.");
                CloseHandle(hPort);
                hPort = (IntPtr)0;
            }
        }


        private void AddPR_Click(object sender, RoutedEventArgs e)
        {
            string extensionName = ExtensionName.Text + ",";
            bool CheckHashFlag = false;
            int AccessFlag = 0;

            if(string.Compare(IsCheckHash.Text,"是") == 0)
            {
                CheckHashFlag = true;
            }
            else if(string.Compare(IsCheckHash.Text, "否") == 0)
            {
                CheckHashFlag = false;
            }
            else
            {
                MessageBox.Show("是否检查哈希值输入错误。");
            }

            if (string.Compare(Access.Text, "明文") == 0)
            {
                AccessFlag = EPT_PR_ACCESS_READ_WRITE;
            }
            else if (string.Compare(Access.Text, "密文") == 0)
            {
                AccessFlag = EPT_PR_ACCESS_BACKUP_RESTORE;
            }
            else if(string.Compare(Access.Text, "无权限") == 0)
            {
                AccessFlag = EPT_PR_ACCESS_NO_ACCESS;
            }
            else
            {
                MessageBox.Show("权限输入错误。");
            }

            if (0 == hPort.ToInt32())
            {
                //MessageBox.Show("New port init.");
                EptUserInitCommPort(ref hPort);
            }

            Thread thread = new Thread(new ThreadStart(GetMessageThread));
            thread.Start();

            EptAddProcessRules(hPort, ProcessName.Text, extensionName, System.Text.RegularExpressions.Regex.Matches(extensionName, ",").Count, AccessFlag, CheckHashFlag);

        }
    }
}
