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

using Proliferation.Fatum;
using Proliferation.CanOpener.Interfaces;

namespace Proliferation.CanOpener
{
    public class UniStream
    {
        static public long TotalArchivesOpened = 0;
        Tree Config = null;
        string FileName;
        FileStream RawStream;
        UniCanInterface OpenArchive = null;
        public Stream CurrentEntryStream;

        public UniStream(string filename, int filetype, Tree config)
        {
            Config = config;
            FileName = filename;

            switch (filetype)
            {
                case 0:
                    OpenArchive = new FileArchiveInterface();
                    break;
                case 1:
                    OpenArchive = new ZIPArchiveInterface();
                    break;
                case 2:
                    OpenArchive = new GZArchiveInterface();
                    break;
                case 3:
                    OpenArchive = new TARArchiveInterface();
                    break;
                case 5:
                    OpenArchive = new SZArchiveInterface();
                    break;
                case 8:
                    OpenArchive = new RARArchiveInterface();
                    break;
                default:
                    OpenArchive = new FileArchiveInterface();
                    break;
            }

            if (!OpenArchive.IsClosed())
            {
                OpenArchive.Close();
            }

            if (FileName.Contains("|"))   // Nexted Archive Indicator
            {
                RawStream = null;
            }
            else
            {   //  Invalid characters in filename

                if (FileName.Contains(":") || FileName.Contains("<") || FileName.Contains(">") || FileName.Contains("*") ||  FileName.Contains("?") || FileName.Contains("/"))   
                {
                    RawStream = null;
                }
                else
                {
                    try
                    {
                        RawStream = File.OpenRead(FileName);
                    }
                    catch (Exception xyz)
                    {
                        RawStream = null;
                    }
                }
            }
        }


        public void Close()
        {
            if (OpenArchive!=null)
            {
                OpenArchive.Close();
            }
            if (RawStream != null) RawStream.Close();
        }

        

        public Boolean findEntry(string filename)
        {
            Boolean result = false;
            Boolean searchover = false;
            string Filename = filename;
            Boolean monofile = false;
            string contents = "";

            OpenArchive.extractEntryData();

            if (!monofile)
            {
                if (Filename.Length > 0)
                {
                    while (Filename[0] == '\\' || Filename[0] == '/')
                    {
                        Filename = Filename.Substring(1);
                    }

                    Filename = CanTools.normalizeDirectory(Filename);

                    while (!searchover)
                    {
                        int res = OpenArchive.nextEntry();
                        if (res != -1)
                        {
                            result = true;
                            searchover = true;
                        }
                        else
                        {
                            searchover = true;
                        }
                    }
                }
            }
            else
            {
                OpenArchive.nextEntry();
                return true;
            }

            return result;
        }

        public int nextEntry()
        {
            return OpenArchive.nextEntry();
        }

        public int Read(byte[] BUFFER, int maxlength)
        {
            int result = 0;
            result = CurrentEntryStream.Read(BUFFER, 0, maxlength);
            return result;
        }

        public void CloseCurrentEntry()
        {
             CurrentEntryStream.Close();
        }

        public Stream OpenCurrentEntry()
        {
            return OpenArchive.OpenCurrentEntry();
        }

        public Tree GetDetails()
        {
            return OpenArchive.getDetails();
        }

        public Tree GetAllFileDetails()
        {
            return OpenArchive.getAllArchiveContent();
        }

        public string getArchiveName()
        {
            return OpenArchive.getArchiveName();
        }

        public DateTime getLastModifiedDate()
        {
            return OpenArchive.getLastModifiedDate();
        }

        public long GetFileLength()
        {
            return OpenArchive.GetFileLength();
        }
    }
}
