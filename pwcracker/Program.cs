using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using pwcracker.hash;

namespace pwcracker
{
    class Program
    {

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("1 for Q1 2 for Q2, 3 to compute SHA1 hash, or 4 to change password for Q4");
            var q = Console.ReadLine();
            if (q == "1")
            {
                Console.WriteLine("enter given ciphertext.");
                var input = Console.ReadLine();
                var c = new Crack(input, "ASCII");

                c.trySha1PIN();
            }
            else if (q == "2")
            {
                Console.WriteLine("enter given ciphertext");
                var input = Console.ReadLine();
                var c = new Crack(input, "ASCII");

                c.trySha1FULL();
            }
            else if (q == "3")
            {
                Console.WriteLine("enter plaintext, including salt");
                var input = Console.ReadLine();

                var d = Encoding.ASCII.GetBytes(input);
                SHA1 sha = new SHA1CryptoServiceProvider();
                var hash = sha.ComputeHash(d);
                Console.WriteLine(Crack.ByteArrToStr(hash));
            }
            else if (q == "4")
            {
                // THIS IS THE SECTION FOR Problem 4

                // take file name
                string filepath;
                using (OpenFileDialog ofd = new OpenFileDialog())
                {
                    ofd.Filter = "SELECT Q4 FILE|*.exe";
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        filepath = ofd.FileName;
                    }
                    else
                    {
                        throw new Exception("Must select a file");
                    }
                }

                // take desired password
                Console.WriteLine("Enter desired password");
                var input = Console.ReadLine();

                // get sha1 of desired password
                var d = Encoding.ASCII.GetBytes(input);
                SHA1 sha = new SHA1CryptoServiceProvider();
                var hash = sha.ComputeHash(d);

                // open file
                using (BinaryWriter writer = new BinaryWriter(File.Open(filepath, FileMode.Open, FileAccess.ReadWrite)))
                {
                    // go to position where hash is stored.
                    // this is always same for my program
                    int offset = 122853;
                    writer.Seek(offset, SeekOrigin.Begin);

                    // overwrite the hash with new hash
                    writer.Write(hash);
                }
                // alert on success
                Console.WriteLine("File has been modified to take your password.");

                //if password contains space, warn user about (un)expected behavior
                if (input.Contains(" "))
                {
                    Console.WriteLine("Warning: new password contains space and the app will exit immidiately.");
                }
            }
            else
            {
                Console.WriteLine("I said 1 or 2 or 3 or 4");
            }
            Console.ReadLine();
        }
    }
}
