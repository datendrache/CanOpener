using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AbsolutionLib.Unraveler
{
    public class CanTools
    {
        static public string getExtension(string filename)
        {
            string result = "";

            int index = filename.IndexOf(".");
            if (index > 0)
            {
                for (int i = filename.Length - 1; i > 0; i--)
                {
                    if (filename[i] == '.')
                    {
                        result = "." + result;
                        i = 0;
                    }
                    else
                    {
                        result = filename[i] + result;
                    }
                }
            }
            return result;
        }

        public static string normalizeDirectory(string incoming)
        {
            return (incoming.Replace("\\", "/"));
        }
    }
}
