//   CanOpener -- A library for identifying and recursively opening archives
//
//   Copyright (C) 2003-2023 Eric Knight
//   This software is distributed under the GNU Public v3 License
//
//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.

//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <https://www.gnu.org/licenses/>.

namespace Proliferation.CanOpener
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
